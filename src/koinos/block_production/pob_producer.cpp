#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/system_timer.hpp>
#include <boost/bind.hpp>

#include <koinos/bigint.hpp>
#include <koinos/block_production/pob_producer.hpp>
#include <koinos/chain/system_call_ids.pb.h>
#include <koinos/contracts/pow/pow.pb.h>
#include <koinos/contracts/token/token.pb.h>
#include <koinos/contracts/vhp/vhp.pb.h>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/protocol/protocol.pb.h>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/util/base58.hpp>
#include <koinos/util/conversion.hpp>
#include <koinos/util/services.hpp>

using namespace std::chrono_literals;

namespace koinos::block_production {

pob_producer::pob_producer( crypto::private_key signing_key,
                            boost::asio::io_context& main_context,
                            boost::asio::io_context& production_context,
                            std::shared_ptr< mq::client > rpc_client,
                            uint64_t resources_lower_bound,
                            uint64_t resources_upper_bound,
                            uint64_t max_inclusion_attempts,
                            bool gossip_production,
                            const std::vector< std::string >& approved_proposals,
                            address_type producer_address ):
    block_producer( signing_key,
                    main_context,
                    production_context,
                    rpc_client,
                    resources_lower_bound,
                    resources_upper_bound,
                    max_inclusion_attempts,
                    gossip_production,
                    approved_proposals ),
    _producer_address( producer_address ),
    _production_timer( _production_context )
{}

pob_producer::~pob_producer() = default;

void pob_producer::produce( const boost::system::error_code& ec, std::shared_ptr< burn_production_bundle > pb )
{
  if( ec == boost::asio::error::operation_aborted )
    return;

  std::lock_guard< std::mutex > lock( _mutex );

  if( pb->time_quantum > std::chrono::system_clock::now() + 5s )
  {
    _production_timer.expires_at( std::chrono::system_clock::now()
                                  + std::chrono::milliseconds{ _auxiliary_data->quantum_length } );
    _production_timer.async_wait( boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error, pb ) );
    return;
  }

  try
  {
    auto timestamp = uint64_t(
      std::chrono::duration_cast< std::chrono::milliseconds >( pb->time_quantum.time_since_epoch() ).count() );

    pb->block.mutable_header()->set_timestamp( timestamp );

    contracts::pob::vrf_payload payload;
    payload.set_seed( pb->metadata.seed() );
    payload.set_block_time( timestamp );

    auto [ proof, proof_hash ] = _signing_key.generate_random_proof( util::converter::as< std::string >( payload ) );

    pb->block.set_id(
      util::converter::as< std::string >( crypto::hash( crypto::multicodec::sha2_256, pb->block.header() ) ) );

    contracts::pob::signature_data signature_data;
    signature_data.set_vrf_hash( util::converter::as< std::string >( proof_hash ) );
    signature_data.set_vrf_proof( proof );
    signature_data.set_signature( util::converter::as< std::string >(
      _signing_key.sign_compact( util::converter::to< crypto::multihash >( pb->block.id() ) ) ) );

    pb->block.set_signature( util::converter::as< std::string >( signature_data ) );

    auto target =
      std::numeric_limits< uint128_t >::max() / util::converter::to< uint128_t >( pb->metadata.difficulty() );

    if( difficulty_met( proof_hash, pb->vhp_balance, target ) )
    {
      LOG( debug ) << "Burn difficulty met at quantum " << timestamp;

      if( submit_block( pb->block ) )
      {
        // A transaction has failed, it has been pruned from the block, immediately retry without the bad transaction
        _production_timer.expires_at( std::chrono::system_clock::now() );
        _production_timer.async_wait(
          boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error, pb ) );
      }
      else
      {
        // We've succeeded, we expect this timer to be usurped by block_accept
        _production_timer.expires_at( std::chrono::system_clock::now() + 5s );
        _production_timer.async_wait(
          boost::bind( &pob_producer::query_production_data, this, boost::asio::placeholders::error ) );
      }
    }
    else
    {
      pb->time_quantum = next_time_quantum( pb->time_quantum );

      _production_timer.expires_at( std::chrono::system_clock::now() );
      _production_timer.async_wait( boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error, pb ) );
    }
  }
  catch( const std::exception& e )
  {
    LOG( warning ) << "Failed producing block, " << e.what() << ", retrying in 5s...";
    _production_timer.expires_at( std::chrono::system_clock::now() + 5s );
    _production_timer.async_wait( boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error, pb ) );
  }
}

std::chrono::system_clock::time_point pob_producer::next_time_quantum( std::chrono::system_clock::time_point tp )
{
  auto time_point =
    std::max( tp, std::chrono::system_clock::time_point{ std::chrono::milliseconds{ _head_block_time.load() } } );
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
  read_contract->set_entry_point( _effective_balance_of_entry_point );

  contracts::vhp::effective_balance_of_arguments args;
  args.set_owner( _producer_address );

  read_contract->set_args( util::converter::as< std::string >( args ) );

  auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

  rpc::chain::chain_response resp;
  KOINOS_ASSERT( resp.ParseFromString( future.get() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", resp.GetTypeName() ) );

  KOINOS_ASSERT( !resp.has_error(),
                 rpc_failure,
                 "error while retrieving VHP balance: ${e}",
                 ( "e", resp.error().message() ) );
  KOINOS_ASSERT( resp.has_read_contract(),
                 rpc_failure,
                 "unexpected RPC response when VHP balance: ${r}",
                 ( "r", resp ) );

  contracts::vhp::effective_balance_of_result balance_result;
  KOINOS_ASSERT( balance_result.ParseFromString( resp.read_contract().result() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", balance_result.GetTypeName() ) );

  return balance_result.value();
}

std::string pob_producer::get_vhp_symbol()
{
  rpc::chain::chain_request req;
  auto read_contract = req.mutable_read_contract();
  read_contract->set_contract_id( _vhp_contract_id );
  read_contract->set_entry_point( _symbol_entry_point );

  auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

  rpc::chain::chain_response resp;
  KOINOS_ASSERT( resp.ParseFromString( future.get() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", resp.GetTypeName() ) );

  KOINOS_ASSERT( !resp.has_error(),
                 rpc_failure,
                 "error while retrieving VHP balance: ${e}",
                 ( "e", resp.error().message() ) );
  KOINOS_ASSERT( resp.has_read_contract(),
                 rpc_failure,
                 "unexpected RPC response when VHP balance: ${r}",
                 ( "r", resp ) );

  contracts::token::symbol_result symbol;
  KOINOS_ASSERT( symbol.ParseFromString( resp.read_contract().result() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", symbol.GetTypeName() ) );

  return symbol.value();
}

uint32_t pob_producer::get_vhp_decimals()
{
  rpc::chain::chain_request req;
  auto read_contract = req.mutable_read_contract();
  read_contract->set_contract_id( _vhp_contract_id );
  read_contract->set_entry_point( _decimals_entry_point );

  auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

  rpc::chain::chain_response resp;
  KOINOS_ASSERT( resp.ParseFromString( future.get() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", resp.GetTypeName() ) );

  KOINOS_ASSERT( !resp.has_error(),
                 rpc_failure,
                 "error while retrieving VHP balance: ${e}",
                 ( "e", resp.error().message() ) );
  KOINOS_ASSERT( resp.has_read_contract(),
                 rpc_failure,
                 "unexpected RPC response when VHP balance: ${r}",
                 ( "r", resp ) );

  contracts::token::decimals_result decimals;
  KOINOS_ASSERT( decimals.ParseFromString( resp.read_contract().result() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", decimals.GetTypeName() ) );

  return decimals.value();
}

address_type pob_producer::get_contract_address( const std::string& name )
{
  rpc::chain::chain_request req;
  auto invoke_system_call = req.mutable_invoke_system_call();
  invoke_system_call->set_id( koinos::chain::get_contract_address );

  contracts::name_service::get_address_arguments args;
  args.set_name( name );
  invoke_system_call->set_args( args.SerializeAsString() );

  auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

  rpc::chain::chain_response resp;
  KOINOS_ASSERT( resp.ParseFromString( future.get() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", resp.GetTypeName() ) );

  KOINOS_ASSERT( !resp.has_error(),
                 rpc_failure,
                 "error while retrieving contract address: ${e}",
                 ( "e", resp.error().message() ) );
  KOINOS_ASSERT( resp.has_invoke_system_call(),
                 rpc_failure,
                 "unexpected RPC response on fetching contract name: ${r}",
                 ( "r", resp ) );

  contracts::name_service::get_address_result result;
  KOINOS_ASSERT( result.ParseFromString( resp.invoke_system_call().value() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", result.GetTypeName() ) );

  return result.value().address();
}

void pob_producer::update_contract_addresses()
{
  auto pob_contract_id = get_contract_address( "pob" );
  auto vhp_contract_id = get_contract_address( "vhp" );

  if( _pob_contract_id != pob_contract_id )
  {
    _pob_contract_id = pob_contract_id;
    LOG( info ) << "PoB contract address: " << util::to_base58( _pob_contract_id );
  }

  if( _vhp_contract_id != vhp_contract_id )
  {
    _vhp_contract_id = vhp_contract_id;
    LOG( info ) << "VHP contract address: " << util::to_base58( _vhp_contract_id );
  }
}

contracts::pob::metadata pob_producer::get_metadata()
{
  rpc::chain::chain_request req;
  auto read_contract = req.mutable_read_contract();
  read_contract->set_contract_id( _pob_contract_id );
  read_contract->set_entry_point( _get_metadata_entry_point );

  auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

  rpc::chain::chain_response resp;
  KOINOS_ASSERT( resp.ParseFromString( future.get() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", resp.GetTypeName() ) );

  KOINOS_ASSERT( !resp.has_error(),
                 rpc_failure,
                 "error while retrieving metadata from the pob contract: ${e}",
                 ( "e", resp.error().message() ) );
  KOINOS_ASSERT( resp.has_read_contract(),
                 rpc_failure,
                 "unexpected RPC response when retrieving metadata: ${r}",
                 ( "r", resp ) );

  contracts::pob::get_metadata_result meta;
  KOINOS_ASSERT( meta.ParseFromString( resp.read_contract().result() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", meta.GetTypeName() ) );

  return meta.value();
}

contracts::pob::consensus_parameters pob_producer::get_consensus_parameters()
{
  rpc::chain::chain_request req;
  auto read_contract = req.mutable_read_contract();
  read_contract->set_contract_id( _pob_contract_id );
  read_contract->set_entry_point( _get_consensus_parameters_entry_point );

  auto future = _rpc_client->rpc( util::service::chain, req.SerializeAsString() );

  rpc::chain::chain_response resp;
  KOINOS_ASSERT( resp.ParseFromString( future.get() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", resp.GetTypeName() ) );

  KOINOS_ASSERT( !resp.has_error(),
                 rpc_failure,
                 "error while retrieving metadata from the pob contract: ${e}",
                 ( "e", resp.error().message() ) );
  KOINOS_ASSERT( resp.has_read_contract(),
                 rpc_failure,
                 "unexpected RPC response when retrieving metadata: ${r}",
                 ( "r", resp ) );

  contracts::pob::get_consensus_parameters_result params;
  KOINOS_ASSERT( params.ParseFromString( resp.read_contract().result() ),
                 deserialization_failure,
                 "unable to deserialize ${t}",
                 ( "t", params.GetTypeName() ) );

  return params.value();
}

bool pob_producer::difficulty_met( const crypto::multihash& hash, uint64_t vhp_balance, uint128_t target )
{
  if( ( util::converter::to< uint256_t >( hash.digest() ) >> 128 ) / vhp_balance < target )
    return true;

  return false;
}

void pob_producer::query_production_data( const boost::system::error_code& ec )
{
  if( ec == boost::asio::error::operation_aborted )
    return;

  std::lock_guard< std::mutex > lock( _mutex );

  try
  {
    auto bundle = next_bundle();
    _production_timer.expires_at( std::chrono::system_clock::now() );
    _production_timer.async_wait(
      boost::bind( &pob_producer::produce, this, boost::asio::placeholders::error, bundle ) );
  }
  catch( const std::exception& e )
  {
    LOG( warning ) << "Failed querying chain, " << e.what() << ", retrying in 5s...";
    _production_timer.expires_at( std::chrono::system_clock::now() + 5s );
    _production_timer.async_wait(
      boost::bind( &pob_producer::query_production_data, this, boost::asio::placeholders::error ) );
  }
}

void pob_producer::query_auxiliary_data( const boost::system::error_code& ec )
{
  if( ec == boost::asio::error::operation_aborted )
    return;

  std::lock_guard< std::mutex > lock( _mutex );

  try
  {
    next_auxiliary_bundle();
    _production_timer.expires_at( std::chrono::system_clock::now() );
    _production_timer.async_wait(
      boost::bind( &pob_producer::query_production_data, this, boost::asio::placeholders::error ) );
  }
  catch( const std::exception& e )
  {
    LOG( warning ) << "Failed querying auxiliary data, " << e.what() << ", retrying in 5s...";
    _production_timer.expires_at( std::chrono::system_clock::now() + 5s );
    _production_timer.async_wait(
      boost::bind( &pob_producer::query_auxiliary_data, this, boost::asio::placeholders::error ) );
  }
}

void pob_producer::next_auxiliary_bundle()
{
  update_contract_addresses();

  auto consensus_params = get_consensus_parameters();
  auto vhp_decimals     = get_vhp_decimals();
  auto vhp_symbol       = get_vhp_symbol();

  KOINOS_ASSERT( consensus_params.target_block_interval() > 0,
                 invalid_parameter,
                 "expected target block interval greater than 0, was ${x}",
                 ( "x", consensus_params.target_block_interval() ) );
  KOINOS_ASSERT( consensus_params.quantum_length() > 0,
                 invalid_parameter,
                 "expected quantum length greater than 0, was ${x}",
                 ( "x", consensus_params.quantum_length() ) );

  constexpr uint32_t max_pow10 = 10;

  KOINOS_ASSERT( !vhp_symbol.empty(), invalid_parameter, "expected VHP symbol to have a value, was empty" );

  KOINOS_ASSERT( vhp_decimals > 0,
                 invalid_parameter,
                 "expected VHP decimals greater than 0, was ${x}",
                 ( "x", vhp_decimals ) );
  KOINOS_ASSERT( vhp_decimals < max_pow10,
                 out_of_bounds_failure,
                 "VHP decimals would exceed static array at index ${i}",
                 ( "i", vhp_decimals ) );

  static uint32_t pow10[ max_pow10 ] =
    { 1, 10, 100, 1'000, 10'000, 100'000, 1'000'000, 10'000'000, 100'000'000, 1'000'000'000 };

  _auxiliary_data = burn_auxiliary_bundle{ .vhp_symbol                = vhp_symbol,
                                           .vhp_precision             = pow10[ vhp_decimals ],
                                           .target_block_interval     = consensus_params.target_block_interval(),
                                           .quantum_length            = consensus_params.quantum_length(),
                                           .quanta_per_block_interval = consensus_params.target_block_interval()
                                                                        / consensus_params.quantum_length() };

  KOINOS_ASSERT( _auxiliary_data->quanta_per_block_interval > 0,
                 invalid_parameter,
                 "expected quanta per block interval greater than 0, was ${x}",
                 ( "x", _auxiliary_data->quanta_per_block_interval ) );

  LOG( info ) << "Target block interval: " << _auxiliary_data->target_block_interval << "ms";
  LOG( info ) << "Quantum length: " << _auxiliary_data->quantum_length << "ms";
}

std::shared_ptr< burn_production_bundle > pob_producer::next_bundle()
{
  update_contract_addresses();

  auto pb = std::make_shared< burn_production_bundle >();

  pb->block        = next_block( _producer_address );
  pb->metadata     = get_metadata();
  pb->vhp_balance  = get_vhp_balance();
  pb->time_quantum = next_time_quantum(
    std::chrono::system_clock::time_point{ std::chrono::milliseconds{ pb->block.header().timestamp() } } );

  KOINOS_ASSERT( pb->vhp_balance > 0,
                 invalid_parameter,
                 "expected VHP balance greater than 0, was ${x}",
                 ( "x", pb->vhp_balance ) );

  auto difficulty = util::converter::to< uint128_t >( pb->metadata.difficulty() );
  KOINOS_ASSERT( difficulty > 0,
                 invalid_parameter,
                 "expected difficulty greater than 0, was ${x}",
                 ( "x", difficulty ) );

  auto vhp = difficulty / _auxiliary_data->quanta_per_block_interval;

  auto now = std::chrono::system_clock::now();

  if( now - _last_vhp_log >= 1min )
  {
    LOG( info ) << "Estimated total " << _auxiliary_data->vhp_symbol << " producing: " << std::setfill( '0' )
                << std::setw( 1 ) << vhp / _auxiliary_data->vhp_precision << "." << std::setw( 8 )
                << vhp % _auxiliary_data->vhp_precision << " " << _auxiliary_data->vhp_symbol;

    LOG( info ) << "Producing with " << std::setfill( '0' ) << std::setw( 1 )
                << pb->vhp_balance / _auxiliary_data->vhp_precision << "." << std::setw( 8 )
                << pb->vhp_balance % _auxiliary_data->vhp_precision << " " << _auxiliary_data->vhp_symbol;

    _last_vhp_log = now;
  }

  return pb;
}

void pob_producer::on_block_accept( const broadcast::block_accepted& bam )
{
  block_producer::on_block_accept( bam );

  if( bam.head() )
  {
    std::lock_guard< std::mutex > lock( _mutex );

    if( bam.live() && bam.block().header().signer() != _producer_address )
      LOG( debug ) << "Received head block - Height: " << bam.block().header().height()
                   << ", ID: " << util::to_hex( bam.block().id() );

    if( _auxiliary_data.has_value() && !_halted )
    {
      _production_timer.expires_at( std::chrono::system_clock::now() );
      _production_timer.async_wait(
        boost::bind( &pob_producer::query_production_data, this, boost::asio::placeholders::error ) );
    }
  }
}

void pob_producer::commence()
{
  std::lock_guard< std::mutex > lock( _mutex );

  _production_timer.expires_at( std::chrono::system_clock::now() );
  _production_timer.async_wait(
    boost::bind( &pob_producer::query_auxiliary_data, this, boost::asio::placeholders::error ) );
}

void pob_producer::halt()
{
  std::lock_guard< std::mutex > lock( _mutex );

  _production_timer.cancel();
}

} // namespace koinos::block_production
