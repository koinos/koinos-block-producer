#include <koinos/block_production/block_producer.hpp>

#include <boost/asio/post.hpp>

#include <koinos/crypto/merkle_tree.hpp>
#include <koinos/mq/util.hpp>
#include <koinos/protocol/protocol.pb.h>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/rpc/mempool/mempool_rpc.pb.h>
#include <koinos/util/conversion.hpp>
#include <koinos/util/services.hpp>

namespace koinos::block_production {

block_producer::block_producer(
   crypto::private_key signing_key,
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   int64_t production_threshold,
   uint64_t resources_lower_bound,
   uint64_t resources_upper_bound,
   uint64_t max_inclusion_attempts ) :
   _signing_key( signing_key ),
   _main_context( main_context ),
   _production_context( production_context ),
   _rpc_client( rpc_client ),
   _production_threshold( production_threshold ),
   _resources_lower_bound( resources_lower_bound ),
   _resources_upper_bound( resources_upper_bound ),
   _max_inclusion_attempts( max_inclusion_attempts )
{
   boost::asio::post( _production_context, std::bind( &block_producer::on_run, this, boost::system::error_code{} ) );
}

block_producer::~block_producer() = default;

void block_producer::on_run( const boost::system::error_code& ec )
{
   if ( ec == boost::asio::error::operation_aborted )
      return;

   if ( !_halted )
      return;

   if ( _production_threshold < 0 )
   {
      LOG(info) << "Starting block production with stale production permitted";
      _halted = false;
      commence();
   }
   else
   {
      LOG(info) << "Awaiting block production threshold of " << _production_threshold << "s from head block time";
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

   fill_block( b );

   protocol::active_block_data active;
   active.set_signer( _signing_key.get_public_key().to_address_bytes() );

   set_merkle_roots( b, active, crypto::multicodec::sha2_256 );

   b.set_active( util::converter::as< std::string >( active ) );

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

      protocol::active_transaction_data active;

      if ( active.ParseFromString( transaction.active() ) )
      {
         if ( active.rc_limit() == 0 )
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
   }

   LOG(info) << "Created block containing " << b.transactions_size() << " " << ( b.transactions_size() == 1 ? "transaction" : "transactions" ) << " utilizing approximately "
             << disk_storage_count << "/" << block_resource_limits.disk_storage_limit() << " disk, "
             << network_bandwidth_count << "/" << block_resource_limits.network_bandwidth_limit() << " network, "
             << compute_bandwidth_count << "/" << block_resource_limits.compute_bandwidth_limit() << " compute";
}

void block_producer::submit_block( protocol::block& b )
{
   rpc::chain::chain_request req;
   auto block_req = req.mutable_submit_block();
   block_req->mutable_block()->CopyFrom( b );

   auto future = _rpc_client->rpc( util::service::chain, util::converter::as< std::string >( req ) );

   rpc::chain::chain_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_error() )
   {
      LOG(warning) << "Error while submitting block: " << resp.error().message();
      return;
   }

   KOINOS_ASSERT( resp.has_submit_block(), rpc_failure, "unexpected RPC response while submitting block: ${r}", ("r", resp) );

   LOG(info) << "Produced block - Height: " << b.header().height() << ", ID: " << util::converter::to< crypto::multihash >( b.id() );
}

void block_producer::set_merkle_roots( const protocol::block& block, protocol::active_block_data& active_data, crypto::multicodec code, crypto::digest_size size )
{
   std::vector< crypto::multihash > transactions;
   transactions.reserve( block.transactions().size() );

   for ( const auto& trx : block.transactions() )
   {
      transactions.emplace_back( crypto::hash( code, trx.active(), size ) );
   }

   auto transaction_merkle_tree = crypto::merkle_tree( code, transactions );

   active_data.set_transaction_merkle_root( util::converter::as< std::string >( transaction_merkle_tree.root()->hash() ) );
}

uint64_t block_producer::now()
{
   auto now = uint64_t( std::chrono::duration_cast< std::chrono::milliseconds >(
      std::chrono::system_clock::now().time_since_epoch()
   ).count() );

   uint64_t last_block_time = _last_block_time;

   return last_block_time > now ? last_block_time : now;
}

void block_producer::on_block_accept( const protocol::block& b )
{
   if ( b.header().timestamp() > _last_block_time )
      _last_block_time = b.header().timestamp();

   if ( _production_threshold >= 0 )
   {
      auto now = std::chrono::duration_cast< std::chrono::milliseconds >(
         std::chrono::system_clock::now().time_since_epoch()
      ).count();

      auto threshold_ms = _production_threshold * 1000;
      auto time_delta   = now - _last_block_time.load();

      if ( time_delta <= threshold_ms )
      {
         if ( _halted )
         {
            LOG(info) << "Within " << _production_threshold << "s of head block time, starting block production";
            _halted = false;
            commence();
         }
      }
      else
      {
         if ( !_halted )
         {
            LOG(info) << "Fell outside " << _production_threshold << "s of head block time, stopping production";
            _halted = true;
            halt();
         }
      }
   }
}

} // koinos::block_production
