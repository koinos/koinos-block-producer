#include <koinos/block_production/block_producer.hpp>

#include <boost/asio/post.hpp>

#include <koinos/crypto/merkle_tree.hpp>
#include <koinos/mq/util.hpp>
#include <koinos/protocol/protocol.pb.h>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/rpc/p2p/p2p_rpc.pb.h>
#include <koinos/rpc/mempool/mempool_rpc.pb.h>
#include <koinos/broadcast/broadcast.pb.h>
#include <koinos/util/conversion.hpp>
#include <koinos/util/hex.hpp>
#include <koinos/util/services.hpp>

namespace koinos::block_production {

block_producer::block_producer(
   crypto::private_key signing_key,
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   uint64_t resources_lower_bound,
   uint64_t resources_upper_bound,
   uint64_t max_inclusion_attempts,
   bool gossip_production ) :
   _signing_key( signing_key ),
   _main_context( main_context ),
   _production_context( production_context ),
   _signals( production_context ),
   _rpc_client( rpc_client ),
   _resources_lower_bound( resources_lower_bound ),
   _resources_upper_bound( resources_upper_bound ),
   _max_inclusion_attempts( max_inclusion_attempts ),
   _gossip_production( gossip_production )
{
   _signals.add( SIGINT );
   _signals.add( SIGTERM );
#if defined(SIGQUIT)
   _signals.add( SIGQUIT );
#endif // defined(SIGQUIT)

   _signals.async_wait( [&]( const boost::system::error_code&, int )
   {
      _halted = true;
      halt();
   } );

   boost::asio::post( _production_context, std::bind( &block_producer::on_run, this, boost::system::error_code{} ) );
}

block_producer::~block_producer() = default;

void block_producer::on_run( const boost::system::error_code& ec )
{
   if ( ec == boost::asio::error::operation_aborted )
      return;

   if ( !_halted )
      return;

   if ( _gossip_production )
   {
      LOG(info) << "Checking p2p gossip status";

      rpc::p2p::p2p_request req;
      req.mutable_get_gossip_status();

      auto future = _rpc_client->rpc( util::service::p2p, util::converter::as< std::string >( req ) );

      rpc::p2p::p2p_response resp;
      resp.ParseFromString( future.get() );

      if ( resp.has_error() )
      {
         KOINOS_THROW( rpc_failure, "unable to retrieve gossip status, ${e}", ("e", resp.error().message()) );
      }

      KOINOS_ASSERT( resp.has_get_gossip_status(), rpc_failure, "unexpected RPC response when retrieving gossip status: ${r}", ("r", resp) );
      const auto& gossip_status = resp.get_gossip_status();

      if ( gossip_status.enabled() )
      {
         LOG(info) << "Gossip is enabled, starting block production";
         _halted = false;
         commence();
      }
   }
   else
   {
      LOG(info) << "Starting block production";
      _halted = false;
      commence();
   }
}

protocol::block block_producer::next_block()
{
   protocol::block b;

   rpc::chain::chain_request req;
   req.mutable_get_head_info();

   auto future = _rpc_client->rpc( util::service::chain, util::converter::as< std::string >( req ) );

   rpc::chain::chain_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_error() )
   {
      KOINOS_THROW( rpc_failure, "unable to retrieve head info, ${e}", ("e", resp.error().message()) );
   }

   KOINOS_ASSERT( resp.has_get_head_info(), rpc_failure, "unexpected RPC response when retrieving head info: ${r}", ("r", resp) );
   const auto& head_info = resp.get_head_info();

   b.mutable_header()->set_previous( head_info.head_topology().id() );
   b.mutable_header()->set_height( head_info.head_topology().height() + 1 );
   b.mutable_header()->set_timestamp( now() );
   b.mutable_header()->set_previous_state_merkle_root( head_info.head_state_merkle_root() );
   b.mutable_header()->set_signer( _signing_key.get_public_key().to_address_bytes() );

   fill_block( b );

   set_merkle_roots( b, crypto::multicodec::sha2_256 );

   return b;
}

void block_producer::fill_block( protocol::block& b )
{
   rpc::mempool::mempool_request mempool_req;
   mempool_req.mutable_get_pending_transactions()->set_limit( 100 );

   rpc::chain::chain_request chain_req;
   chain_req.mutable_get_resource_limits();

   auto future  = _rpc_client->rpc( util::service::mempool, util::converter::as< std::string >( mempool_req ) );
   auto future2 = _rpc_client->rpc( util::service::chain, util::converter::as< std::string >( chain_req ) );

   rpc::mempool::mempool_response mempool_resp;

   if ( !mempool_resp.ParseFromString( future.get() ) )
   {
      KOINOS_THROW( rpc_failure, "unable to parse mempool response" );
   }

   if ( mempool_resp.has_error() )
   {
      KOINOS_THROW( rpc_failure, "unable to retrieve pending transactions, ${e}", ("e", mempool_resp.error().message()) );
   }

   KOINOS_ASSERT( mempool_resp.has_get_pending_transactions(), rpc_failure, "unexpected RPC response when retrieving pending transactions from mempool", ("r", mempool_resp) );
   const auto& pending_transactions = mempool_resp.get_pending_transactions();

   rpc::chain::chain_response chain_resp;

   if ( !chain_resp.ParseFromString( future2.get() ) )
   {
      KOINOS_THROW( rpc_failure, "unable to parse chain response" );
   }

   if ( chain_resp.has_error() )
   {
      KOINOS_THROW( rpc_failure, "unable to retrieve block resources, ${e}", ("e", mempool_resp.error().message()) );
   }

   KOINOS_ASSERT( chain_resp.has_get_resource_limits(), rpc_failure, "unexpected RPC response when retrieving block resources from chain", ("r", chain_resp) );
   const auto& block_resource_limits = chain_resp.get_resource_limits().resource_limit_data();

   uint64_t disk_storage_count      = 0;
   uint64_t network_bandwidth_count = 0;
   uint64_t compute_bandwidth_count = 0;

   for ( int ptransaction_index = 0; ptransaction_index < pending_transactions.pending_transactions_size(); ptransaction_index++ )
   {
      // Only try to process a set number of transactions
      if ( ptransaction_index > _max_inclusion_attempts - 1 )
         break;

      // If we fill at least 75% of a given block resource we proceed
      if ( disk_storage_count >= block_resource_limits.disk_storage_limit() * _resources_lower_bound / 100 )
         break;

      if ( network_bandwidth_count >= block_resource_limits.network_bandwidth_limit() * _resources_lower_bound / 100 )
         break;

      if ( compute_bandwidth_count >= block_resource_limits.compute_bandwidth_limit() * _resources_lower_bound / 100 )
         break;

      const auto& ptransaction = pending_transactions.pending_transactions( ptransaction_index );
      const auto& transaction = ptransaction.transaction();

      if ( transaction.header().rc_limit() == 0 )
         continue;

      auto new_disk_storage_count      = ptransaction.disk_storage_used() + disk_storage_count;
      auto new_network_bandwidth_count = ptransaction.network_bandwidth_used() + network_bandwidth_count;
      auto new_compute_bandwidth_count = ptransaction.compute_bandwidth_used() + compute_bandwidth_count;

      bool disk_storage_within_bounds      = new_disk_storage_count      <= block_resource_limits.disk_storage_limit()      * _resources_upper_bound / 100;
      bool network_bandwidth_within_bounds = new_network_bandwidth_count <= block_resource_limits.network_bandwidth_limit() * _resources_upper_bound / 100;
      bool compute_bandwidth_within_bounds = new_compute_bandwidth_count <= block_resource_limits.compute_bandwidth_limit() * _resources_upper_bound / 100;

      if ( disk_storage_within_bounds && network_bandwidth_within_bounds && compute_bandwidth_within_bounds )
      {
         *b.add_transactions()   = transaction;
         disk_storage_count      = new_disk_storage_count;
         network_bandwidth_count = new_network_bandwidth_count;
         compute_bandwidth_count = new_compute_bandwidth_count;
      }
   }

   LOG(info) << "Created block containing " << b.transactions_size() << " " << ( b.transactions_size() == 1 ? "transaction" : "transactions" ) << " utilizing approximately "
             << disk_storage_count << "/" << block_resource_limits.disk_storage_limit() << " disk, "
             << network_bandwidth_count << "/" << block_resource_limits.network_bandwidth_limit() << " network, "
             << compute_bandwidth_count << "/" << block_resource_limits.compute_bandwidth_limit() << " compute";
}

void block_producer::trim_block( protocol::block& b, const std::string& trx_id )
{
   auto trxs = b.mutable_transactions();

   for ( size_t i = 0; i < trxs->size(); i++ )
   {
      if ( trxs->at( i ).id() == trx_id )
      {
         trxs->DeleteSubrange( i, trxs->size() - i );
         return;
      }
   }
}

bool block_producer::submit_block( protocol::block& b )
{
   rpc::chain::chain_request req;
   auto block_req = req.mutable_submit_block();
   block_req->mutable_block()->CopyFrom( b );

   auto future = _rpc_client->rpc( util::service::chain, util::converter::as< std::string >( req ) );

   rpc::chain::chain_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_error() )
   {
      if ( resp.error().data().length() > 0 )
      {
         try
         {
            auto data = nlohmann::json::parse( resp.error().data() );

            if ( data.find( "logs" ) != data.end() )
            {
               const auto& logs = data[ "logs" ];
               for ( const auto& log : logs )
                  LOG(warning) << "Log: " << log;
            }

            if ( data.find( "transaction_id" ) != data.end() )
            {
               const auto& trx_id = data[ "transaction_id" ];
               LOG(warning) << "Error on applying transaction " << trx_id << ": " << resp.error().message();

               trim_block( b, util::from_hex< std::string >( trx_id ) );
               set_merkle_roots( b, crypto::multicodec::sha2_256 );

               return true;
            }
         }
         catch ( const std::exception& e )
         {
            LOG(warning) << "Unable to trim block, " << e.what();
         }
      }

      LOG(warning) << "Error while submitting block: " << resp.error().message();
      return false;
   }

   KOINOS_ASSERT( resp.has_submit_block(), rpc_failure, "unexpected RPC response while submitting block: ${r}", ("r", resp) );

   LOG(info) << "Produced block - Height: " << b.header().height() << ", ID: " << util::converter::to< crypto::multihash >( b.id() );
   return false;
}

void block_producer::set_merkle_roots( protocol::block& block, crypto::multicodec code, crypto::digest_size size )
{
   std::vector< crypto::multihash > hashes;
   hashes.reserve( block.transactions().size() * 2 );

   for ( const auto& trx : block.transactions() )
   {
      hashes.emplace_back( crypto::hash( code, trx.header(), size ) );
      hashes.emplace_back( crypto::hash( code, trx.signatures(), size ) );
   }

   auto transaction_merkle_tree = crypto::merkle_tree( code, hashes );

   block.mutable_header()->set_transaction_merkle_root( util::converter::as< std::string >( transaction_merkle_tree.root()->hash() ) );
}

uint64_t block_producer::now()
{
   auto now = uint64_t( std::chrono::duration_cast< std::chrono::milliseconds >(
      std::chrono::system_clock::now().time_since_epoch()
   ).count() );

   uint64_t last_block_time = _last_block_time;

   return last_block_time > now ? last_block_time : now;
}

void block_producer::on_block_accept( const protocol::block& b ) { }

void block_producer::on_gossip_status( const broadcast::gossip_status& gs )
{
   if ( !_gossip_production )
   {
      return;
   }

   if ( gs.enabled() )
   {
      if ( _halted )
      {
         LOG(info) << "Gossip enabled, starting block production";
         _halted = false;
         commence();
      }
   }
   else
   {
      if ( !_halted )
      {
         LOG(info) << "Gossip disabled, halting block production";
         _halted = true;
         halt();
      }
   }

}

} // koinos::block_production
