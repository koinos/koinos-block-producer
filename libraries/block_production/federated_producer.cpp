#include <koinos/block_production/federated_producer.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>

#include <boost/asio/post.hpp>

#define KOINOS_BLOCK_TIME_MS 5000

namespace koinos::block_production {

federated_producer::federated_producer( boost::asio::io_context& ioc, std::shared_ptr< mq::client > rpc_client ) :
   block_producer( ioc, rpc_client ),
   _production_interval( KOINOS_BLOCK_TIME_MS ),
   _timer( _io_context, _production_interval )
{
   boost::asio::post( _io_context, std::bind( &federated_producer::produce, this, boost::system::error_code{} ) );
}

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
      LOG(error) << e.what();
   }

   _timer.expires_at( _timer.expires_at() + _production_interval );
   _timer.async_wait( std::bind( &federated_producer::produce, this, std::placeholders::_1 ) );
}

} // koinos::block_production

