#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/system_timer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/bind.hpp>

#include <koinos/bigint.hpp>
#include <koinos/block_production/pob_producer.hpp>
#include <koinos/contracts/pow/pow.pb.h>
#include <koinos/contracts/token/token.pb.h>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/protocol/protocol.pb.h>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/util/conversion.hpp>
#include <koinos/util/services.hpp>

using namespace std::chrono_literals;

namespace koinos::block_production {

pob_producer::pob_producer(
   crypto::private_key signing_key,
   boost::asio::io_context& main_context,
   boost::asio::io_context& production_context,
   std::shared_ptr< mq::client > rpc_client,
   uint64_t resources_lower_bound,
   uint64_t resources_upper_bound,
   uint64_t max_inclusion_attempts,
   bool gossip_production,
   const std::vector< std::string >& approved_proposals,
   contract_id_type pob_contract_id,
   contract_id_type vhp_contract_id ) :
      block_producer(
         signing_key,
         main_context,
         production_context,
         rpc_client,
         resources_lower_bound,
         resources_upper_bound,
         max_inclusion_attempts,
         gossip_production,
         approved_proposals
      ),
      _pob_contract_id( pob_contract_id ),
      _vhp_contract_id( vhp_contract_id ),
      _production_timer( _production_context ) {}

pob_producer::~pob_producer() = default;

void pob_producer::produce( const boost::system::error_code& ec )
{
   if ( ec == boost::asio::error::operation_aborted )
      return;

   std::lock_guard< std::mutex > guard( _time_quantum_mutex );

   auto time_point = next_time_quantum( _last_time_quantum );
   if ( time_point > std::chrono::system_clock::now() + 5s )
   {
      _production_timer.expires_at( std::chrono::system_clock::now() + 10ms );
      _production_timer.async_wait( boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error ) );
      return;
   }

   std::chrono::system_clock::time_point retry_time = std::chrono::system_clock::now();

   try
   {
      auto block = next_block();

      auto metadata = get_metadata();
      LOG(info) << "Metadata: " << metadata;

      auto vhp_balance = get_vhp_balance();
      LOG(info) << "VHP balance: " << vhp_balance << " VHPs";

      auto difficulty = util::converter::to< uint256_t >( metadata.difficulty() );

      auto time_quantum = uint64_t( time_point.time_since_epoch().count() );
      LOG(info) << "Time quantum: " << time_quantum;

      block.mutable_header()->set_timestamp( time_quantum );

      contracts::pob::vrf_payload payload;
      payload.set_seed( metadata.seed() );
      payload.set_block_time( time_quantum );

      auto [ proof, proof_hash ] = _signing_key.generate_random_proof( util::converter::as< std::string >( payload ) );

      contracts::pob::signature_data signature_data;
      signature_data.set_vrf_hash( util::converter::as< std::string >( proof_hash ) );
      signature_data.set_vrf_proof( proof );

      uint64_t block_submission_attempts = 0;
      if ( difficulty_met( proof_hash, vhp_balance, difficulty ) )
      {
         LOG(info) << "Difficulty met";
         do
         {
            block_submission_attempts++;

            block.set_id( util::converter::as< std::string >( crypto::hash( crypto::multicodec::sha2_256, block.header() ) ) );

            signature_data.set_signature( util::converter::as< std::string >( _signing_key.sign_compact( util::converter::to< crypto::multihash >( block.id() ) ) ) );

            block.set_signature( util::converter::as< std::string >( signature_data ) );

            LOG(info) << "Attempting block submission (" << block_submission_attempts << ")";
         }
         while ( submit_block( block ) && block_submission_attempts <= 3 );
      }
      else
      {
         LOG(info) << "Difficulty not met";
      }

      _last_time_quantum = time_point;
   }
   catch ( const std::exception& e )
   {
      LOG(warning) << e.what() << ", retrying in 1s...";
      retry_time = std::chrono::system_clock::now() + 1s;
   }

   _production_timer.expires_at( retry_time );
   _production_timer.async_wait( boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error ) );
}

std::chrono::system_clock::time_point pob_producer::next_time_quantum( std::chrono::system_clock::time_point tp )
{
   auto time_point = std::max( tp, std::chrono::system_clock::now() );
   auto time_ms    = std::chrono::duration_cast< std::chrono::milliseconds >( time_point.time_since_epoch() ).count();
   auto remainder  = time_ms % 10;
   time_ms        += 10 - remainder;
   return std::chrono::system_clock::time_point{ std::chrono::milliseconds{ time_ms } };
}

uint64_t pob_producer::get_vhp_balance()
{
   rpc::chain::chain_request req;
   auto read_contract = req.mutable_read_contract();
   read_contract->set_contract_id( _vhp_contract_id );
   read_contract->set_entry_point( _balance_of_entry_point );

   contracts::token::balance_of_arguments args;
   args.set_owner( util::converter::as< std::string >( _signing_key.get_public_key().to_address_bytes() ) );

   read_contract->set_args( util::converter::as< std::string >( args ) );

   auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

   rpc::chain::chain_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_error() )
   {
      KOINOS_THROW( rpc_failure, "error while retrieving VHP balance: ${e}", ("e", resp.error().message()) );
   }

   KOINOS_ASSERT( resp.has_read_contract(), rpc_failure, "unexpected RPC response when VHP balance: ${r}", ("r", resp) );

   contracts::token::balance_of_result balance_result;
   balance_result.ParseFromString( resp.read_contract().result() );
   return balance_result.value();
}

contracts::pob::metadata pob_producer::get_metadata()
{
   rpc::chain::chain_request req;
   auto read_contract = req.mutable_read_contract();
   read_contract->set_contract_id( _pob_contract_id );
   read_contract->set_entry_point( _get_metadata_entry_point );

   auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

   rpc::chain::chain_response resp;
   resp.ParseFromString( future.get() );

   if ( resp.has_error() )
   {
      KOINOS_THROW( rpc_failure, "error while retrieving metadata from the pob contract: ${e}", ("e", resp.error().message()) );
   }

   KOINOS_ASSERT( resp.has_read_contract(), rpc_failure, "unexpected RPC response when retrieving metadata: ${r}", ("r", resp) );

   contracts::pob::get_metadata_result meta;
   meta.ParseFromString( resp.read_contract().result() );
   return meta.value();
}

bool pob_producer::difficulty_met( const crypto::multihash& hash, uint64_t vhp_balance, uint256_t target )
{
   if ( util::converter::to< uint256_t >( hash.digest() ) / vhp_balance <= target )
      return true;

   return false;
}

void pob_producer::on_block_accept( const protocol::block& b )
{
   block_producer::on_block_accept( b );

   std::lock_guard< std::mutex > guard( _time_quantum_mutex );

   _last_time_quantum = std::chrono::system_clock::time_point{ std::chrono::milliseconds{ b.header().timestamp() } };

   _production_timer.expires_at( std::chrono::system_clock::now() );
   _production_timer.async_wait( boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error ) );
}

void pob_producer::commence()
{
   _production_timer.expires_at( std::chrono::system_clock::now() );
   _production_timer.async_wait( boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error ) );
}

void pob_producer::halt()
{
   _production_timer.cancel();
}


} // koinos::block_production
