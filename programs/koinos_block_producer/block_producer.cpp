#include <koinos/block_producer.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/mq/util.hpp>
#include <koinos/pack/classes.hpp>
#include <koinos/util.hpp>

#include <thread>

#define KOINOS_BLOCK_TIME_MS 5000

namespace koinos {

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

void set_block_merkle_roots( protocol::block& block, uint64_t code, uint64_t size = 0 )
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

void sign_block( protocol::block& block, crypto::private_key& block_signing_key )
{
   pack::to_variable_blob(
      block.signature_data,
      block_signing_key.sign_compact( block.id )
   );
}

static timestamp_type timestamp_now()
{
   return timestamp_type{
      uint64_t( std::chrono::duration_cast< std::chrono::milliseconds >(
         std::chrono::system_clock::now().time_since_epoch()
      ).count() )
   };
}

namespace detail {

struct block_producer_impl
{
   block_producer_impl( boost::asio::io_context& ioc, std::shared_ptr< mq::client > rpc_client );
   ~block_producer_impl();

   void start();
   void stop();

   void production_loop(const boost::system::error_code& ec);
   void produce_block();

   std::unique_ptr< std::thread >   _main_thread;
   std::shared_ptr< mq::client >    _rpc_client;
   crypto::private_key              _block_signing_key;
   boost::asio::io_context&         _io_context;
   boost::posix_time::milliseconds  _production_interval;
   boost::asio::deadline_timer      _timer;
};

block_producer_impl::block_producer_impl( boost::asio::io_context& ioc, std::shared_ptr< mq::client > rpc_client ) :
   _rpc_client( rpc_client ),
   _io_context( ioc ),
   _production_interval( KOINOS_BLOCK_TIME_MS ),
   _timer( _io_context, _production_interval )
{
   // TODO: Get key from cli args/encrypted key file
   std::string seed = "test seed";
   _block_signing_key = crypto::private_key::regenerate( crypto::hash_str( CRYPTO_SHA2_256_ID, seed.c_str(), seed.size() ) );
}

block_producer_impl::~block_producer_impl()
{
   stop();
}

void block_producer_impl::start()
{
   _timer.async_wait( std::bind( &block_producer_impl::production_loop, this, std::placeholders::_1 ) );
}

void block_producer_impl::stop()
{
   _timer.cancel();
}

void block_producer_impl::production_loop(const boost::system::error_code& ec)
{
   if ( ec != boost::asio::error::operation_aborted )
   {
      produce_block();

      _timer.expires_at( _timer.expires_at() + _production_interval );
      _timer.async_wait( std::bind( &block_producer_impl::production_loop, this, std::placeholders::_1 ) );
   }
}

void block_producer_impl::produce_block()
{
   try
   {
      // Make block header
      rpc::chain::submit_block_request block_req;
      block_req.verify_passive_data = true;
      block_req.verify_block_signature = true;
      block_req.verify_transaction_signatures = true;

      nlohmann::json j;
      pack::to_json( j, rpc::chain::chain_rpc_request{ rpc::chain::get_head_info_request{} } );
      auto future = _rpc_client->rpc( service::chain, j.dump() );

      rpc::chain::chain_rpc_response resp;
      pack::from_json( nlohmann::json::parse( future.get() ), resp );
      auto head_info = std::get< rpc::chain::get_head_info_response >( resp );

      // Initialize header
      block_req.block.header.previous  = head_info.head_topology.id;
      block_req.block.header.height    = head_info.head_topology.height + 1;
      block_req.block.header.timestamp = timestamp_now();

      j.clear();
      pack::to_json( j, rpc::mempool::mempool_rpc_request{ rpc::mempool::get_pending_transactions_request{ .limit = 100 } } );
      future = _rpc_client->rpc( service::mempool, j.dump() );

      rpc::mempool::mempool_rpc_response m_resp;
      pack::from_json( nlohmann::json::parse( future.get() ), m_resp );
      auto mempool = std::get< rpc::mempool::get_pending_transactions_response >( m_resp );

      // TODO: Limit transaction inclusion via block size
      block_req.block.transactions.insert( block_req.block.transactions.end(), mempool.transactions.begin(), mempool.transactions.end() );

      block_req.block.passive_data = protocol::passive_block_data();
      block_req.block.active_data = protocol::active_block_data();

      set_block_merkle_roots( block_req.block, CRYPTO_SHA2_256_ID );

      // Store hash of header and active as ID
      block_req.block.id = crypto::hash_n( CRYPTO_SHA2_256_ID, block_req.block.header, block_req.block.active_data );

      sign_block( block_req.block, _block_signing_key );

      j.clear();
      pack::to_json( j, rpc::chain::chain_rpc_request{ block_req } );
      future = _rpc_client->rpc( service::chain, j.dump() );

      pack::from_json( nlohmann::json::parse( future.get() ), resp );
      std::visit(
         koinos::overloaded {
            [&]( const rpc::chain::submit_block_response& )
            {
               LOG(info) << "Produced block - Height: " << block_req.block.header.height << ", ID: " << block_req.block.id;
            },
            [&]( const rpc::chain::chain_error_response& e )
            {
               LOG(info) << "Error producing block: " << e.error_text;
               LOG(info) << e.error_data;
            },
            [&]( const auto& p )
            {
               LOG(error) << "Unexpected RPC response: " << p;
            }
      }, resp );
   }
   catch ( const std::exception& e )
   {
      LOG(error) << e.what();
   }
}

} // detail

block_producer::block_producer( boost::asio::io_context& ioc, std::shared_ptr< mq::client > rpc_client ) :
   _my( std::make_unique< detail::block_producer_impl >( ioc, rpc_client ) )
{}

block_producer::~block_producer() {}

void block_producer::start()
{
   _my->start();
}

void block_producer::stop()
{
   _my->stop();
}

} // koinos
