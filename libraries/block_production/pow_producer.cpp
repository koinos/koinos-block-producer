#include <algorithm>
#include <chrono>
#include <iostream>

#include <boost/asio/post.hpp>

#include <koinos/block_production/pow_producer.hpp>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/pack/classes.hpp>

#define TARGET_BLOCK_INTERVAL_MS 10000

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

const uint32_t get_difficulty_entry_point = 1249216561;

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

std::string uint256_to_hex( const koinos::uint256_t& x )
{
   std::vector<uint8_t> v;
   std::string result;
   char digit[] = "0123456789abcdef";

   // msv_first = true means it's exported in big-endian bit order
   boost::multiprecision::export_bits(x, std::back_inserter(v), 8);
   size_t n = v.size();
   for( size_t i=0; i<v.size(); i++ )
   {
      uint8_t c = v[i];
      result += digit[(c >> 4) & 0x0f];
      result += digit[ c       & 0x0f];
   }
   return result;
}

std::string hashrate_to_string( double hashrate )
{
   std::string suffix = "H/s";

   if ( hashrate > hashrate::terahash )
   {
      hashrate /= hashrate::terahash;
      suffix = "TH/s";
   }
   else if ( hashrate > hashrate::gigahash )
   {
      hashrate /= hashrate::gigahash;
      suffix = "GH/s";
   }
   else if ( hashrate > hashrate::megahash )
   {
      hashrate /= hashrate::megahash;
      suffix = "MH/s";
   }
   else if ( hashrate > hashrate::kilohash )
   {
      hashrate /= hashrate::kilohash;
      suffix = "KH/s";
   }
   return std::to_string(hashrate) + " " + suffix;
}

std::string compute_network_hashrate( const koinos::uint256_t& difficulty )
{
   double diff = difficulty.convert_to<double>();
   double one = std::numeric_limits< uint256_t >::max().convert_to<double>();
   double tries_to_produce = one / diff;

   double target_block_interval_s = TARGET_BLOCK_INTERVAL_MS / 1000.0;
   double tries_per_second = tries_to_produce / target_block_interval_s;

   return hashrate_to_string(tries_per_second);
}

pow_producer::pow_producer(
   crypto::private_key signing_key,
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   contract_id_type pow_contract_id,
   std::size_t worker_groups ) :
   block_producer( signing_key, main_context, production_context, rpc_client ),
   _pow_contract_id( pow_contract_id ),
   _update_timer( _main_context ),
   _error_timer( _production_context )
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

   boost::asio::post( _production_context, std::bind( &pow_producer::produce, this, boost::system::error_code{} ) );
   _update_timer.expires_from_now( hashrate::update_interval + 2500ms );
   _update_timer.async_wait( std::bind( &pow_producer::display_hashrate, this, std::placeholders::_1 ) );
}

pow_producer::~pow_producer() = default;

void pow_producer::display_hashrate( const boost::system::error_code& ec )
{
   if ( ec == boost::asio::error::operation_aborted )
      return;

   if ( _hashing )
   {
      double total_hashes = 0;
      for ( auto it = _worker_hashrate.begin(); it != _worker_hashrate.end(); ++it )
         total_hashes += it->second.load();

      total_hashes /= hashrate::update_interval.count();

      LOG(info) << "Hashrate: " << hashrate_to_string( total_hashes );
   }

   _update_timer.expires_from_now( hashrate::update_interval );
   _update_timer.async_wait( std::bind( &pow_producer::display_hashrate, this, std::placeholders::_1 ) );
}

void pow_producer::produce( const boost::system::error_code& ec )
{
   if ( ec == boost::asio::error::operation_aborted )
      return;

   auto done  = std::make_shared< std::atomic< bool > >( false );
   auto nonce = std::make_shared< std::optional< uint256_t > >();

   try
   {
      auto block = next_block();
      fill_block( block );
      auto difficulty = get_difficulty();
      block.id = crypto::hash_n( CRYPTO_SHA2_256_ID, block.header, block.active_data );

      LOG(info) << "Received difficulty target: 0x" << uint256_to_hex(difficulty);
      LOG(info) << "Network hashrate (MH/s): " << compute_network_hashrate(difficulty);

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

         _hashing = true;

         while ( !_cv.wait_for( lock, 1s, [&]()
         {
            service_was_halted = _production_context.stopped();
            block_is_stale     = _last_known_height >= block.header.height;

            return *done || service_was_halted || block_is_stale;
         } ) );

         _hashing = false;

         if ( service_was_halted )
            return;

         if ( block_is_stale )
         {
            LOG(info) << "Block is stale, retrieving new head";
            *done = true;
            boost::asio::post( _production_context, std::bind( &pow_producer::produce, this, boost::system::error_code{} ) );
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
      _error_wait_time = 5s;
   }
   catch ( const std::exception& e )
   {
      *done = true;
      _hashing = false;

      LOG(warning) << e.what() << ", retrying in " << _error_wait_time.load().count() << "s";

      _error_timer.expires_from_now( _error_wait_time.load() );
      _error_timer.async_wait( std::bind( &pow_producer::produce, this, std::placeholders::_1 ) );

      // Exponential backoff, max wait time 30 seconds
      auto next_wait_time = std::min( uint64_t( _error_wait_time.load().count() * 2 ), uint64_t( 30 ) );
      _error_wait_time = std::chrono::seconds( next_wait_time );
      return;
   }

   boost::asio::post( _production_context, std::bind( &pow_producer::produce, this, boost::system::error_code{} ) );
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

      auto blob = pack::to_variable_blob( current_nonce );
      blob.insert( blob.end(), block.id.digest.begin(), block.id.digest.end() );
      auto hash = crypto::hash_str( CRYPTO_SHA2_256_ID, blob.data(), blob.size() );

      if ( difficulty_met( hash, difficulty ) )
      {
         std::unique_lock< std::mutex > lock( _cv_mutex );
         if ( !*done )
         {
            *nonce = current_nonce;
            *done  = true;
            _cv.notify_one();
         }
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
   req.contract_id = _pow_contract_id;
   req.entry_point = get_difficulty_entry_point;

   pack::json j;
   pack::to_json( j, rpc::chain::chain_rpc_request{ req } );
   auto future = _rpc_client->rpc( service::chain, j.dump() );

   rpc::chain::chain_rpc_response resp;
   pack::from_json( pack::json::parse( future.get() ), resp );

   rpc::chain::read_contract_response contract_response;
   std::visit(
      koinos::overloaded {
         [&]( const rpc::chain::read_contract_response& cr )
         {
            contract_response = cr;
         },
         [&]( const rpc::chain::chain_error_response& ce )
         {
            KOINOS_THROW( koinos::exception, "Error while retrieving difficulty from the pow contract: ${e}", ("e", ce.error_text) );
         },
         [&]( const auto& p )
         {
            KOINOS_THROW( koinos::exception, "Unexpected RPC response while retrieving difficulty from the pow contract" );
         }
   }, resp );

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
   block_producer::on_block_accept( b );

   {
      std::unique_lock< std::mutex > lock( _cv_mutex );
      _last_known_height = b.header.height;
      _cv.notify_one();
   }
}

} // koinos::block_production
