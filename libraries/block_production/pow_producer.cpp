#include <chrono>

#include <boost/asio/post.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <koinos/block_production/pow_producer.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>

using namespace std::chrono_literals;
using boost::multiprecision::uint128_t;

#define KOINOS_SHOW_HASHRATE_MS 15000

namespace koinos::block_production {

pow_producer::pow_producer(
   boost::asio::io_context& ioc,
   std::shared_ptr< mq::client > rpc_client,
   boost::asio::io_context& main_context,
   uint64_t work_groups ) :
   block_producer( ioc, rpc_client ),
   _main_context( main_context ),
   _hashrate_interval( KOINOS_SHOW_HASHRATE_MS ),
   _timer( _main_context, _hashrate_interval )
{
   constexpr uint128_t max_nonce = std::numeric_limits< uint64_t >::max();
   for ( uint64_t worker_index = 0; worker_index < work_groups; worker_index++ )
   {
      uint128_t start = max_nonce * worker_index / work_groups;
      uint128_t end   = max_nonce * ( worker_index + 1 ) / work_groups;
      _work_groups.emplace_back( start.convert_to< uint64_t >(), end.convert_to< uint64_t >() );
      LOG(info) << "Work group " << worker_index << ": [" << start.convert_to< uint64_t >() << ", " << end.convert_to< uint64_t >() << "]";
      _worker_hashes[ worker_index ].store( 0, std::memory_order_relaxed );
   }

   boost::asio::post( _io_context, std::bind( &pow_producer::produce, this ) );
   _timer.expires_at( _timer.expires_at() + _hashrate_interval );
   _timer.async_wait( std::bind( &pow_producer::show_hashrate, this, std::placeholders::_1 ) );
}

pow_producer::~pow_producer() = default;

void pow_producer::show_hashrate( const boost::system::error_code& ec )
{
   if ( ec == boost::asio::error::operation_aborted )
      return;

   double total_hashes = 0;
   for ( auto it = _worker_hashes.begin(); it != _worker_hashes.end(); ++it )
      total_hashes += it->second.load( std::memory_order_relaxed );

   total_hashes /= 5;
   std::string suffix = "H/s";

   if ( total_hashes > 1000000000000 )
   {
      total_hashes /= 1000000000000;
      suffix = "TH/s";
   }
   else if ( total_hashes > 1000000000 )
   {
      total_hashes /= 1000000000;
      suffix = "GH/s";
   }
   else if ( total_hashes > 1000000 )
   {
      total_hashes /= 1000000;
      suffix = "MH/s";
   }
   else if ( total_hashes > 1000 )
   {
      total_hashes /= 1000;
      suffix = "KH/s";
   }

   LOG(info) << "Hashrate: " << total_hashes << " " << suffix;

   _timer.expires_at( _timer.expires_at() + _hashrate_interval );
   _timer.async_wait( std::bind( &pow_producer::show_hashrate, this, std::placeholders::_1 ) );
}

void pow_producer::produce()
{
   _nonce_found.store( false, std::memory_order_relaxed );
   _nonce.reset();

   try
   {
      auto block = next_block();
      fill_block( block );
      auto difficulty = get_difficulty();

      uint64_t worker_index = 0;
      for ( auto& [ start, end ] : _work_groups )
      {
         boost::asio::post(
            _io_context,
            std::bind(
               &pow_producer::find_nonce,
               this,
               worker_index++,
               block,
               difficulty,
               start,
               end
            )
         );
      }

      {
         auto lock = std::unique_lock< std::mutex >( _nonce_mutex );
         while ( !_cv.wait_for( lock, 1s, [&]()
         {
            return _nonce_found.load( std::memory_order_relaxed ) || _io_context.stopped();
         } ) );

         if ( _io_context.stopped() )
            return;

         KOINOS_ASSERT( _nonce.has_value(), koinos::exception, "Expected nonce to have a value" );
      }

      LOG(info) << "Found nonce: " << *_nonce;
      block.id = crypto::hash_n( CRYPTO_SHA2_256_ID, block.header, block.active_data, *_nonce );
      pack::to_variable_blob( block.signature_data, *_nonce );
      pack::to_variable_blob( block.signature_data, _signing_key.sign_compact( block.id ), true );
      submit_block( block );
   }
   catch ( const std::exception& e )
   {
      LOG(warning) << e.what();
   }

   boost::asio::post( _io_context, std::bind( &pow_producer::produce, this ) );
}

void pow_producer::find_nonce( uint64_t worker_index, const protocol::block& block, uint32_t difficulty, uint64_t start, uint64_t end )
{
   auto begin_time  = std::chrono::steady_clock::now();
   auto begin_nonce = start;

   variable_blob base_blob;
   pack::to_variable_blob( block.header );
   pack::to_variable_blob( base_blob, block.active_data, true );

   for ( uint64_t nonce = start; nonce < end; nonce++ )
   {
      if ( _nonce_found.load( std::memory_order_relaxed ) || _io_context.stopped() )
         break;

      variable_blob blob( base_blob );
      pack::to_variable_blob( blob, nonce, true );
      auto hash = crypto::hash( CRYPTO_SHA2_256_ID, blob );

      if ( difficulty_met( hash, difficulty ) )
      {
         std::unique_lock< std::mutex > lock( _nonce_mutex );
         _nonce = nonce;
         _nonce_found.store( true, std::memory_order_relaxed );
         _cv.notify_one();
      }

      if ( auto now = std::chrono::steady_clock::now(); now - begin_time > 5s )
      {
         _worker_hashes[ worker_index ].store( nonce - begin_nonce, std::memory_order_relaxed );
         begin_time = now;
         begin_nonce = nonce;
      }
   }
}

uint32_t pow_producer::get_difficulty()
{
   KOINOS_TODO( "Retrieve difficulty from chain" );
   return 20;
}

bool pow_producer::difficulty_met( const multihash& hash, uint32_t difficulty )
{
   KOINOS_TODO( "Implement dynamic difficulty" );
   if (
      uint8_t( hash.digest[0] ) == uint8_t( 0x00 ) &&
      uint8_t( hash.digest[1] ) == uint8_t( 0x00 ) &&
      uint8_t( hash.digest[2] ) == uint8_t( 0x00 ) &&
      uint8_t( hash.digest[3] ) <= uint8_t( 0x0F )
      )
      return true;
   return false;
}

} // koinos::block_production
