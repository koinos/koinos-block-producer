#include <koinos/block_production/block_producer.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/mq/util.hpp>
#include <koinos/pack/classes.hpp>
#include <koinos/util.hpp>

namespace koinos::block_production {

block_producer::block_producer(
   crypto::private_key signing_key,
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client ) :
   _signing_key( signing_key ),
   _main_context( main_context ),
   _production_context( production_context ),
   _rpc_client( rpc_client )
{
}

block_producer::~block_producer() = default;

protocol::block block_producer::next_block()
{
   protocol::block b;

   pack::json j;
   pack::to_json( j, rpc::chain::chain_rpc_request{ rpc::chain::get_head_info_request{} } );
   auto future = _rpc_client->rpc( service::chain, j.dump() );

   rpc::chain::chain_rpc_response resp;
   pack::from_json( pack::json::parse( future.get() ), resp );

   rpc::chain::get_head_info_response head_info;
   std::visit(
      koinos::overloaded {
         [&]( const rpc::chain::get_head_info_response& hi )
         {
            head_info = hi;
         },
         [&]( const rpc::chain::chain_error_response& ce )
         {
            KOINOS_THROW( koinos::exception, "Error while retrieving head info: ${e}", ("e", ce.error_text) );
         },
         [&]( const auto& p )
         {
            KOINOS_THROW( koinos::exception, "Unexpected RPC response when retrieving head info" );
         }
   }, resp );

   b.header.previous  = head_info.head_topology.id;
   b.header.height    = head_info.head_topology.height + 1;
   b.header.timestamp = now();

   return b;
}

void block_producer::fill_block( protocol::block& b )
{
   pack::json j;
   pack::to_json( j, rpc::mempool::mempool_rpc_request{ rpc::mempool::get_pending_transactions_request{ .limit = 100 } } );
   auto future = _rpc_client->rpc( service::mempool, j.dump() );

   rpc::mempool::mempool_rpc_response resp;
   pack::from_json( pack::json::parse( future.get() ), resp );

   rpc::mempool::get_pending_transactions_response mempool;
   std::visit(
      koinos::overloaded {
         [&]( const rpc::mempool::get_pending_transactions_response& mpr )
         {
            mempool = mpr;
         },
         [&]( const rpc::mempool::mempool_error_response& ce )
         {
            KOINOS_THROW( koinos::exception, "Error while retrieving transaction from the mempool: ${e}", ("e", ce.error_text) );
         },
         [&]( const auto& p )
         {
            KOINOS_THROW( koinos::exception, "Unexpected RPC response when retrieving transaction from the mempool" );
         }
   }, resp );

   const uint128 max_block_resources             = 1000000000;
   const std::size_t max_transactions_to_process = 100;
   uint128 block_resources                       = 0;

   for ( std::size_t transaction_index = 0; transaction_index < mempool.transactions.size(); transaction_index++ )
   {
      // Only try to process a set number of blocks
      if ( transaction_index > max_transactions_to_process - 1 )
         break;

      // If we fill at least 75% of the block we proceed
      if ( block_resources >= max_block_resources * 75 / 100 )
         break;

      auto& transaction = mempool.transactions.at( transaction_index );

      transaction.active_data.unbox();

      auto new_block_resources = block_resources + transaction.active_data->resource_limit;

      if ( new_block_resources <= max_block_resources )
      {
         b.transactions.push_back( transaction );
         block_resources = new_block_resources;
      }
   }

   b.passive_data = protocol::passive_block_data();
   b.active_data  = protocol::active_block_data();

   b.active_data.make_mutable();

   auto signer_address   = _signing_key.get_public_key().to_address();
   b.active_data->signer = protocol::account_type( signer_address.begin(), signer_address.end() );

   set_merkle_roots( b, CRYPTO_SHA2_256_ID );
}

void block_producer::submit_block( protocol::block& b )
{
   rpc::chain::submit_block_request block_req;
   block_req.block = b;
   block_req.verify_passive_data = true;
   block_req.verify_block_signature = true;
   block_req.verify_transaction_signatures = true;

   pack::json j;
   pack::to_json( j, rpc::chain::chain_rpc_request{ block_req } );
   auto future = _rpc_client->rpc( service::chain, j.dump() );

   rpc::chain::chain_rpc_response resp;
   pack::from_json( pack::json::parse( future.get() ), resp );
   std::visit(
      koinos::overloaded {
         [&]( const rpc::chain::submit_block_response& )
         {
            LOG(info) << "Produced block - Height: " << block_req.block.header.height << ", ID: " << block_req.block.id;
         },
         [&]( const rpc::chain::chain_error_response& ce )
         {
            LOG(warning) << "Error while submitting block: " << ce.error_text;
         },
         [&]( const auto& p )
         {
            KOINOS_THROW( koinos::exception, "Unexpected RPC response while submitting block" );
         }
   }, resp );
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

void block_producer::set_merkle_roots( protocol::block& block, uint64_t code, uint64_t size )
{
   std::vector< multihash > trx_active_hashes( block.transactions.size() );
   std::vector< multihash > passive_hashes( 2 * ( block.transactions.size() + 1 ) );

   passive_hashes[0] = crypto::hash( code, block.passive_data, size );
   passive_hashes[1] = crypto::empty_hash( code, size );

   // Hash transaction actives, passives, and signatures for merkle roots
   for ( size_t i = 0; i < block.transactions.size(); i++ )
   {
      trx_active_hashes[i]      = crypto::hash(      code, block.transactions[i].active_data,    size );
      passive_hashes[2*(i+1)]   = crypto::hash(      code, block.transactions[i].passive_data,   size );
      passive_hashes[2*(i+1)+1] = crypto::hash_blob( code, block.transactions[i].signature_data, size );
   }

   crypto::merkle_hash_leaves( trx_active_hashes, code, size );
   crypto::merkle_hash_leaves( passive_hashes,    code, size );

   block.active_data->transaction_merkle_root  = trx_active_hashes[0];
   block.active_data->passive_data_merkle_root = passive_hashes[0];
}

timestamp_type block_producer::now()
{
   auto now = timestamp_type {
      uint64_t( std::chrono::duration_cast< std::chrono::milliseconds >(
         std::chrono::system_clock::now().time_since_epoch()
      ).count() )
   };

   auto last_block_time = timestamp_type{ _last_block_time };

   return last_block_time > now ? last_block_time : now;
}

void block_producer::on_block_accept( const protocol::block& b )
{
   if ( b.header.timestamp.t > _last_block_time )
      _last_block_time = b.header.timestamp.t;
}

} // koinos::block_production
