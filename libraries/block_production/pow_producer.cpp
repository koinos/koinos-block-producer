#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>

#include <boost/asio/post.hpp>

#include <koinos/bigint.hpp>
#include <koinos/block_production/pow_producer.hpp>
#include <koinos/contracts/pow/pow.pb.h>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/protocol/protocol.pb.h>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/util/conversion.hpp>
#include <koinos/util/services.hpp>

const uint32_t get_difficulty_entrypoint = 1249216561;

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
   crypto::private_key signing_key,
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   int64_t production_threshold,
   uint64_t resources_lower_bound,
   uint64_t resources_upper_bound,
   uint64_t max_inclusion_attempts,
   bool gossip_production,
   contract_id_type pow_contract_id,
   std::size_t worker_groups ) :
      block_producer(
         signing_key,
         main_context,
         production_context,
         rpc_client,
         production_threshold,
         resources_lower_bound,
         resources_upper_bound,
         max_inclusion_attempts,
         gossip_production
      ),
      _pow_contract_id( pow_contract_id ),
      _update_timer( _main_context ),
      _error_timer( _production_context ),
      _num_worker_groups( worker_groups )
{
   constexpr uint512_t max_nonce = std::numeric_limits< uint256_t >::max();
   for ( std::size_t worker_index = 0; worker_index < _num_worker_groups; worker_index++ )
   {
      uint512_t start = max_nonce * worker_index / _num_worker_groups;
      uint512_t end   = max_nonce * ( worker_index + 1 ) / _num_worker_groups;

      _worker_groups.emplace_back( start.convert_to< uint256_t >(), end.convert_to< uint256_t >() );
      _worker_hashrate[ worker_index ].store( 0 );

      LOG(info) << "Work group " << worker_index << ": [" << start.convert_to< uint256_t >() << ", " << end.convert_to< uint256_t >() << "]";
   }
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

      do
      {
         auto diff_meta = get_difficulty_meta();
         auto target = util::converter::to< uint256_t >( diff_meta.target() );

         block.set_id( util::converter::as< std::string >( crypto::hash( crypto::multicodec::sha2_256, block.header() ) ) );

         LOG(info) << "Difficulty target: 0x" << std::setfill( '0' ) << std::setw( 64 ) << std::hex << target;
         LOG(info) << "Network hashrate: " << compute_network_hashrate( diff_meta );

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
                  target,
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
               service_was_halted = _production_context.stopped() || _halted;
               block_is_stale     = _last_known_height >= block.header().height();

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

         KOINOS_ASSERT( nonce->has_value(), nonce_failure, "expected nonce to contain a value" );

         auto block_nonce = nonce->value();

         LOG(info) << "Found nonce: 0x" << std::setfill( '0' ) << std::setw( 64 ) << std::hex << block_nonce;
         LOG(info) << "Proof: " << crypto::hash( crypto::multicodec::sha2_256, block_nonce, block.id() );

         contracts::pow::pow_signature_data pow_data;
         pow_data.set_nonce( util::converter::as< std::string >( block_nonce ) );
         pow_data.set_recoverable_signature( util::converter::as< std::string >( _signing_key.sign_compact( util::converter::to< crypto::multihash >( block.id() ) ) ) );

         block.set_signature( util::converter::as< std::string >( pow_data ) );
      }
      while( submit_block( block ) );

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
   uint256_t target,
   uint256_t start,
   uint256_t end,
   std::shared_ptr< std::optional< uint256_t > > nonce,
   std::shared_ptr< std::atomic< bool > > done )
{
   auto begin_time  = std::chrono::steady_clock::now();
   auto begin_nonce = start;
   auto id = util::converter::to< crypto::multihash >( block.id() );

   for ( uint256_t current_nonce = start; current_nonce < end; current_nonce++ )
   {
      if ( *done || _production_context.stopped() || _halted )
         break;

      auto proof = hash( crypto::multicodec::sha2_256, current_nonce, id );

      if ( target_met( proof, target ) )
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

contracts::pow::difficulty_metadata pow_producer::get_difficulty_meta()
{
   rpc::chain::chain_request req;
   auto read_contract = req.mutable_read_contract();
   read_contract->set_contract_id( _pow_contract_id );
   read_contract->set_entry_point( get_difficulty_entrypoint );

   auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

   rpc::chain::chain_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_error() )
   {
      KOINOS_THROW( rpc_failure, "error while retrieving difficulty from the pow contract: ${e}", ("e", resp.error().message()) );
   }

   KOINOS_ASSERT( resp.has_read_contract(), rpc_failure, "unexpected RPC response when retrieving difficulty: ${r}", ("r", resp) );

   contracts::pow::get_difficulty_metadata_result meta;
   meta.ParseFromString( resp.read_contract().result() );
   return meta.value();
}

bool pow_producer::target_met( const crypto::multihash& hash, uint256_t target )
{
   if ( util::converter::to< uint256_t >( hash.digest() ) <= target )
      return true;

   return false;
}

void pow_producer::on_block_accept( const protocol::block& b )
{
   block_producer::on_block_accept( b );

   {
      std::unique_lock< std::mutex > lock( _cv_mutex );
      _last_known_height = b.header().height();
      _cv.notify_one();
   }
}

std::string pow_producer::hashrate_to_string( double hashrate )
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

   return std::to_string( hashrate ) + " " + suffix;
}

std::string pow_producer::compute_network_hashrate( const contracts::pow::difficulty_metadata& meta )
{
   auto hashrate = util::converter::to< uint256_t >( meta.difficulty() ) / meta.target_block_interval();
   return hashrate_to_string( double( hashrate ) );
}

void pow_producer::commence()
{
   boost::asio::post( _production_context, std::bind( &pow_producer::produce, this, boost::system::error_code{} ) );
   _update_timer.expires_from_now( hashrate::update_interval + 2500ms );
   _update_timer.async_wait( std::bind( &pow_producer::display_hashrate, this, std::placeholders::_1 ) );
}

void pow_producer::halt()
{
   _update_timer.cancel();
}


} // koinos::block_production
