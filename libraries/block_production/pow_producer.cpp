#include <bitset>
#include <chrono>
#include <iostream>

#include <boost/asio/post.hpp>

#include <koinos/block_production/pow_producer.hpp>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/pack/classes.hpp>

struct difficulty_metadata
{
   koinos::uint256        current_difficulty = 0;
   koinos::timestamp_type last_block_time    = koinos::timestamp_type( 0 );
   koinos::timestamp_type block_window_time  = koinos::timestamp_type( 0 );
   koinos::uint32         averaging_window   = 0;
};

KOINOS_REFLECT( difficulty_metadata,
   (current_difficulty)
   (last_block_time)
   (block_window_time)
   (averaging_window)
)

struct pow_signature_data
{
   koinos::uint256          nonce;
   koinos::fixed_blob< 65 > recoverable_signature;
};

KOINOS_REFLECT( pow_signature_data, (nonce)(recoverable_signature) )

using namespace std::chrono_literals;

namespace koinos::block_production {

namespace hashrate
{
   constexpr double terahash = 1.0e12;
   constexpr double gigahash = 1.0e9;
   constexpr double megahash = 1.0e6;
   constexpr double kilohash = 1.0e3;

   constexpr std::chrono::seconds update_interval = 2s;
}

pow_producer::pow_producer(
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   std::size_t worker_groups ) :
   block_producer( main_context, production_context, rpc_client ),
   _timer( _main_context )
{
   constexpr uint512_t max_nonce = std::numeric_limits< uint256_t >::max();
   for ( std::size_t worker_index = 0; worker_index < worker_groups; worker_index++ )
   {
      uint512_t start = max_nonce * worker_index / worker_groups;
      uint512_t end   = max_nonce * ( worker_index + 1 ) / worker_groups;

      _worker_groups.emplace_back( start.convert_to< uint256_t >(), end.convert_to< uint256_t >() );
      _worker_hashrate[ worker_index ].store( 0 );

      LOG(info) << "Work group " << worker_index << ": [" << start.convert_to< uint256_t >() << ", " << end.convert_to< uint256_t >() << "]";
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
   auto done  = std::make_shared< std::atomic< bool > >();
   auto nonce = std::make_shared< std::optional< uint256_t > >();

   try
   {
      auto block = next_block();
      fill_block( block );
      auto difficulty = get_difficulty();
      block.id = crypto::hash_n( CRYPTO_SHA2_256_ID, block.header, block.active_data );

      LOG(info) << "Received difficulty: " << difficulty;

      for ( std::size_t worker_index = 0; worker_index < _worker_groups.size(); worker_index++ )
      {
         const auto& [ start, end ] = _worker_groups.at( worker_index );
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
               nonce,
               done
            )
         );
      }

      {
         auto lock = std::unique_lock< std::mutex >( _cv_mutex );

         bool service_was_halted = false;
         bool block_is_stale     = false;

         while ( !_cv.wait_for( lock, 1s, [&]()
         {
            service_was_halted = _production_context.stopped();
            block_is_stale     = _last_known_height >= block.header.height;

            return *done || service_was_halted || block_is_stale;
         } ) );

         if ( service_was_halted )
            return;

         if ( block_is_stale )
         {
            LOG(info) << "Block is stale, retrieving new head";
            *done = true;
            boost::asio::post( _production_context, std::bind( &pow_producer::produce, this ) );
            return;
         }
      }

      KOINOS_ASSERT( nonce->has_value(), koinos::exception, "Expected nonce to contain a value" );

      auto block_nonce = nonce->value();

      LOG(info) << "Found nonce: " << block_nonce;
      LOG(info) << "Proof: " << crypto::hash_n( CRYPTO_SHA2_256_ID, block_nonce, block.id.digest );

      pow_signature_data pow_data;
      pow_data.nonce = block_nonce;
      pow_data.recoverable_signature = _signing_key.sign_compact( block.id );

      pack::to_variable_blob( block.signature_data, pow_data );

      submit_block( block );
   }
   catch ( const std::exception& e )
   {
      *done = true;
      LOG(warning) << e.what();
   }

   boost::asio::post( _production_context, std::bind( &pow_producer::produce, this ) );
}

void pow_producer::find_nonce(
   std::size_t worker_index,
   const protocol::block& block,
   uint256_t difficulty,
   uint256_t start,
   uint256_t end,
   std::shared_ptr< std::optional< uint256_t > > nonce,
   std::shared_ptr< std::atomic< bool > > done )
{
   auto begin_time  = std::chrono::steady_clock::now();
   auto begin_nonce = start;

   for ( uint256_t current_nonce = start; current_nonce < end; current_nonce++ )
   {
      if ( *done || _production_context.stopped() )
         break;

      auto hash = crypto::hash_n( CRYPTO_SHA2_256_ID, current_nonce, block.id.digest );

      if ( difficulty_met( hash, difficulty ) )
      {
         std::unique_lock< std::mutex > lock( _cv_mutex );
         *nonce = current_nonce;
         *done  = true;
         _cv.notify_one();
      }

      if ( auto now = std::chrono::steady_clock::now(); now - begin_time > hashrate::update_interval )
      {
         auto hashes = current_nonce - begin_nonce;
         begin_time  = now;
         begin_nonce = current_nonce;
         _worker_hashrate[ worker_index ] = hashes.convert_to< uint64_t >();
      }
   }
}

uint256_t pow_producer::get_difficulty()
{
   rpc::chain::read_contract_request req;
   req.contract_id = pack::from_variable_blob< contract_id_type >( pack::to_variable_blob( uint160_t( 1 ) ) );
   req.entry_point = 1249216561;

   pack::json j;
   pack::to_json( j, rpc::chain::chain_rpc_request{ req } );
   auto future = _rpc_client->rpc( service::chain, j.dump() );

   rpc::chain::chain_rpc_response resp;
   pack::from_json( pack::json::parse( future.get() ), resp );
   auto contract_response = std::get< rpc::chain::read_contract_response >( resp );

   auto metadata = pack::from_variable_blob< difficulty_metadata >( contract_response.result );

   return metadata.current_difficulty;
}

bool pow_producer::difficulty_met( const multihash& hash, uint256_t difficulty )
{
   if ( pack::from_variable_blob< uint256_t >( hash.digest ) <= difficulty )
      return true;

   return false;
}

void pow_producer::on_block_accept( const protocol::block& b )
{
   std::unique_lock< std::mutex > lock( _cv_mutex );
   _last_known_height = b.header.height;
   _cv.notify_one();
}

} // koinos::block_production