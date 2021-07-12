#include <koinos/block_production/federated_producer.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>

#include <boost/asio/post.hpp>

using namespace std::chrono_literals;

namespace koinos::block_production {

namespace block_time
{
   constexpr std::chrono::seconds interval = 5s;
}

federated_producer::federated_producer(
   crypto::private_key signing_key,
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   int64_t production_threshold ) :
   block_producer( signing_key, main_context, production_context, rpc_client, production_threshold ),
   _timer( _production_context ) {}

federated_producer::~federated_producer() = default;

void federated_producer::produce( const boost::system::error_code& ec )
{
   if ( ec == boost::asio::error::operation_aborted )
      return;

   try
   {
      auto block = next_block();
      fill_block( block );
      block.id = crypto::hash_n( CRYPTO_SHA2_256_ID, block.header, block.active_data );
      pack::to_variable_blob( block.signature_data, _signing_key.sign_compact( block.id ) );
      submit_block( block );
   }
   catch ( const std::exception& e )
   {
      LOG(warning) << e.what();
   }

   _timer.expires_from_now( block_time::interval );
   _timer.async_wait( std::bind( &federated_producer::produce, this, std::placeholders::_1 ) );
}

void federated_producer::commence()
{
   boost::asio::post( _production_context, std::bind( &federated_producer::produce, this, boost::system::error_code{} ) );
}

void federated_producer::halt()
{
   _timer.cancel();
}

} // koinos::block_production
