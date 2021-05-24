#include <chrono>

#include <boost/asio/post.hpp>

#include <koinos/block_production/pow_producer.hpp>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/pack/classes.hpp>

using namespace std::chrono_literals;

namespace koinos::block_production {

namespace hashrate
{
   constexpr double terahash = 1.0e12;
   constexpr double gigahash = 1.0e9;
   constexpr double megahash = 1.0e6;
   constexpr double kilohash = 1.0e3;

   constexpr std::chrono::seconds update_interval = 5s;
}

pow_producer::pow_producer(
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   std::size_t worker_groups ) :
   block_producer( main_context, production_context, rpc_client ),
   _timer( _main_context )
{
   constexpr uint128_t max_nonce = std::numeric_limits< uint64_t >::max();
   for ( std::size_t worker_index = 0; worker_index < worker_groups; worker_index++ )
   {
      uint128_t start = max_nonce * worker_index / worker_groups;
      uint128_t end   = max_nonce * ( worker_index + 1 ) / worker_groups;
      _worker_groups.emplace_back( start.convert_to< uint64_t >(), end.convert_to< uint64_t >() );
      LOG(info) << "Work group " << worker_index << ": [" << start.convert_to< uint64_t >() << ", " << end.convert_to< uint64_t >() << "]";
      _worker_hashrate[ worker_index ].store( 0 );
   }

   boost::asio::post( _production_context, std::bind( &pow_producer::produce, this ) );
   _timer.expires_from_now( hashrate::update_interval + 2500ms );
   _timer.async_wait( std::bind( &pow_producer::display_hashrate, this, std::placeholders::_1 ) );
}

pow_producer::~pow_producer() = default;

void pow_producer::display_hashrate( const boost::system::error_code& ec )
{
   if ( ec == boost::asio::error::operation_aborted )
      return;

   double total_hashes = 0;
   for ( auto it = _worker_hashrate.begin(); it != _worker_hashrate.end(); ++it )
      total_hashes += it->second.load();

   total_hashes /= hashrate::update_interval.count();
   std::string suffix = "H/s";

   if ( total_hashes > hashrate::terahash )
   {
      total_hashes /= hashrate::terahash;
      suffix = "TH/s";
   }
   else if ( total_hashes > hashrate::gigahash )
   {
      total_hashes /= hashrate::gigahash;
      suffix = "GH/s";
   }
   else if ( total_hashes > hashrate::megahash )
   {
      total_hashes /= hashrate::megahash;
      suffix = "MH/s";
   }
   else if ( total_hashes > hashrate::kilohash )
   {
      total_hashes /= hashrate::kilohash;
      suffix = "KH/s";
   }

   LOG(info) << "Hashrate: " << total_hashes << " " << suffix;

   _timer.expires_from_now( hashrate::update_interval );
   _timer.async_wait( std::bind( &pow_producer::display_hashrate, this, std::placeholders::_1 ) );
}

void pow_producer::produce()
{
   try
   {
      auto block = next_block();
      fill_block( block );
      auto difficulty = get_difficulty();

      auto nonce_return = std::make_shared< nonce_type >();

      for ( std::size_t worker_index = 0; worker_index < _worker_groups.size(); worker_index++ )
      {
         auto& [ start, end ] = _worker_groups.at( worker_index );
         boost::asio::post(
            _production_context,
            std::bind(
               &pow_producer::find_nonce,
               this,
               worker_index++,
               block,
               difficulty,
               start,
               end,
               nonce_return
            )
         );
      }

      {
         auto lock = std::unique_lock< std::mutex >( _cv_mutex );
         while ( !_cv.wait_for( lock, 1s, [&]()
         {
            return nonce_return->load().has_value() || _production_context.stopped();
         } ) );

         if ( _production_context.stopped() )
            return;
      }

      auto nonce = *nonce_return->load();

      LOG(info) << "Found nonce: " << nonce;

      block.id = crypto::hash_n(
         CRYPTO_SHA2_256_ID,
         block.header,
         block.active_data,
         nonce
      );

      pack::to_variable_blob( block.signature_data, nonce );
      pack::to_variable_blob( block.signature_data, _signing_key.sign_compact( block.id ), true );

      submit_block( block );
   }
   catch ( const std::exception& e )
   {
      LOG(warning) << e.what();
   }

   boost::asio::post( _production_context, std::bind( &pow_producer::produce, this ) );
}

void pow_producer::find_nonce(
   std::size_t worker_index,
   const protocol::block& block,
   uint32_t difficulty,
   uint64_t start,
   uint64_t end,
   std::shared_ptr< nonce_type > nonce_return )
{
   auto begin_time  = std::chrono::steady_clock::now();
   auto begin_nonce = start;

   variable_blob base_blob;
   pack::to_variable_blob( block.header );
   pack::to_variable_blob( base_blob, block.active_data, true );

   for ( uint64_t nonce = start; nonce < end; nonce++ )
   {
      if ( nonce_return->load().has_value() || _production_context.stopped() )
         break;

      variable_blob blob( base_blob );
      pack::to_variable_blob( blob, nonce, true );
      auto hash = crypto::hash( CRYPTO_SHA2_256_ID, blob );

      if ( difficulty_met( hash, difficulty ) )
      {
         std::unique_lock< std::mutex > lock( _cv_mutex );
         nonce_return->store( nonce );
         _cv.notify_one();
      }

      if ( auto now = std::chrono::steady_clock::now(); now - begin_time > hashrate::update_interval )
      {
         _worker_hashrate[ worker_index ].store( nonce - begin_nonce );
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
