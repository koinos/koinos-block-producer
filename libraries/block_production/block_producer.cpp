#include <koinos/block_production/block_producer.hpp>

#include <boost/asio/post.hpp>

#include <koinos/crypto/merkle_tree.hpp>
#include <koinos/mq/util.hpp>
#include <koinos/protocol/protocol.pb.h>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/rpc/mempool/mempool_rpc.pb.h>
#include <koinos/util.hpp>

namespace koinos::block_production {

block_producer::block_producer(
   crypto::private_key signing_key,
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   int64_t production_threshold ) :
   _signing_key( signing_key ),
   _main_context( main_context ),
   _production_context( production_context ),
   _rpc_client( rpc_client ),
   _production_threshold( production_threshold )
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

   rpc::chain::chain_rpc_request req;
   req.mutable_get_head_info();

   std::string s;
   req.SerializeToString( &s );
   auto future = _rpc_client->rpc( service::chain, s );

   rpc::chain::chain_rpc_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_chain_error() )
   {
      KOINOS_THROW( koinos::exception, "Error while retrieving head info: ${e}", ("e", resp.chain_error().message()) );
   }

   KOINOS_ASSERT( resp.has_get_head_info(), koinos::exception, "Unexpected RPC response when retrieving head info: ${r}", ("r", resp) );
   const auto& head_info = resp.get_head_info();

   b.mutable_header()->set_previous( resp.get_head_info().head_topology().id() );
   b.mutable_header()->set_height( resp.get_head_info().head_topology().height() + 1 );
   b.mutable_header()->set_timestamp( now() );

   return b;
}

void block_producer::fill_block( protocol::block& b )
{
   rpc::mempool::mempool_rpc_request req;
   req.mutable_get_pending_transactions()->set_limit( 100 );

   std::string s;
   req.SerializeToString( &s );
   auto future = _rpc_client->rpc( service::mempool, s );

   rpc::mempool::mempool_rpc_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_mempool_error() )
   {
      KOINOS_THROW( koinos::exception, "Error while retrieving head info: ${e}", ("e", resp.mempool_error().message()) );
   }

   KOINOS_ASSERT( resp.has_get_pending_transactions(), koinos::exception, "Unexpected RPC response when retrieving head info", ("r", resp) );
   const auto& pending_transactions = resp.get_pending_transactions();

   const uint64_t max_block_resources    = 100'000'000;
   const int max_transactions_to_process = 100;
   uint64_t block_resources              = 0;

   //for( const auto& trx : pending_transactions.transactions() )
   //{
   //
   //}

   for ( int transaction_index = 0; transaction_index < pending_transactions.transactions_size(); transaction_index++ )
   {
      // Only try to process a set number of transactions
      if ( transaction_index > max_transactions_to_process - 1 )
         break;

      // If we fill at least 75% of the block we proceed
      if ( block_resources >= max_block_resources * 75 / 100 )
         break;

      const auto& transaction = pending_transactions.transactions( transaction_index );

      if ( !transaction.active().has_native() )
         continue;

      auto new_block_resources = block_resources + transaction.active().native().resource_limit();

      if ( new_block_resources <= max_block_resources )
      {
         *b.add_transactions() = transaction;
         block_resources = new_block_resources;
      }
   }

   b.mutable_passive()->mutable_native();
   b.mutable_active()->mutable_native();

   auto signer_address   = _signing_key.get_public_key().to_address();
   b.mutable_active()->mutable_native()->set_signer( std::string( signer_address.begin(), signer_address.end() ) );

   set_merkle_roots( b, crypto::multicodec::sha2_256 );
}

void block_producer::submit_block( protocol::block& b )
{
   rpc::chain::chain_rpc_request req;
   auto block_req = req.mutable_submit_block();
   block_req->set_allocated_block( &b );
   block_req->set_verify_passive_data( true );
   block_req->set_verify_block_signature( true );
   block_req->set_verify_transaction_signature( true );

   std::string s;
   req.SerializeToString( &s );
   auto future = _rpc_client->rpc( service::chain, s );

   rpc::chain::chain_rpc_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_chain_error() )
   {
      LOG(warning) << "Error while submitting block: " << resp.chain_error().message();
      return;
   }

   KOINOS_ASSERT( resp.has_submit_block(), koinos::exception, "Unexpected RPC response while submitting block: ${r}", ("r", resp) );

   LOG(info) << "Produced block - Height: " << b.header().height() << ", ID: " << b.id();
}

//
// +-----------+      +--------------+      +-------------------------+      +---------------------+
// | Block sig | ---> | Block active | ---> | Transaction merkle root | ---> | Transaction actives |
// +-----------+      +--------------+      +-------------------------+      +---------------------+
//                           |
//                           V
//                +----------------------+      +----------------------+
//                |                      | ---> |     Block passive    |
//                |                      |      +----------------------+
//                |                      |
//                |                      |      +----------------------+
//                | Passives merkle root | ---> | Transaction passives |
//                |                      |      +----------------------+
//                |                      |
//                |                      |      +----------------------+
//                |                      | ---> |   Transaction sigs   |
//                +----------------------+      +----------------------+
//

void block_producer::set_merkle_roots( protocol::block& block, crypto::multicodec code, uint64_t size )
{

   std::vector< const protocol::transaction* > transactions( block.transactions().size() );
   std::vector< passive_hash_target > passives( 2 * ( block.transactions().size() + 1 ) );

   passives.emplace_back( &block.passive() );
   passives.emplace_back( empty_hash_t() );

   for ( const auto& trx : block.transactions() )
   {
      transactions.push_back( &trx );
      passives.emplace_back( &trx.passive() );
      passives.emplace_back( &trx.signature_data() );
   }

   auto transaction_merkle_tree = crypto::merkle_tree( code, transactions );
   auto passives_merkle_tree = crypto::merkle_tree( code, passives );

   block.mutable_active()->mutable_native()->set_transaction_merkle_root( transaction_merkle_tree.root()->hash().as< std::string >() );
   block.mutable_active()->mutable_native()->set_passive_data_merkle_root( passives_merkle_tree.root()->hash().as< std::string >() );
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
