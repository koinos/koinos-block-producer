#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <variant>

#include <boost/asio/system_timer.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <koinos/block_production/block_producer.hpp>
#include <koinos/contracts/pob/pob.pb.h>

namespace koinos::block_production {

using boost::multiprecision::uint512_t;
using boost::multiprecision::uint256_t;

using address_type = std::string;

struct burn_production_bundle {
   koinos::protocol::block block;
   koinos::contracts::pob::metadata metadata;
   uint64_t vhp_balance;
   std::chrono::system_clock::time_point time_quantum;
};

struct burn_auxiliary_bundle {
   std::string vhp_symbol;
   uint32_t vhp_precision;
   uint32_t target_block_interval;
   uint32_t quantum_length;
   uint32_t quanta_per_block_interval;
};

class pob_producer : public block_producer
{
public:
   pob_producer(
      crypto::private_key signing_key,
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client,
      uint64_t resources_lower_bound,
      uint64_t resources_upper_bound,
      uint64_t max_inclusion_attempts,
      bool gossip_production,
      const std::vector< std::string >& approved_proposals,
      address_type pob_contract_id,
      address_type vhp_contract_id,
      address_type producer_address
   );
   ~pob_producer();

   virtual void on_block_accept( const broadcast::block_accepted& bam ) override;

protected:
   void commence() override;
   void halt() override;

private:
   boost::asio::system_timer                     _production_timer;
   const address_type                            _pob_contract_id;
   const address_type                            _vhp_contract_id;
   const address_type                            _producer_address;
   const uint32_t                                _get_metadata_entry_point = 0xfcf7a68f;
   const uint32_t                                _get_consensus_parameters_entry_point = 0x5fd7ac0f;
   const uint32_t                                _balance_of_entry_point = 0x5c721497;
   const uint32_t                                _decimals_entry_point = 0xee80fd2f;
   const uint32_t                                _symbol_entry_point = 0xb76a7ca1;
   std::optional< burn_auxiliary_bundle >        _auxiliary_data;
   std::mutex                                    _mutex;

   void next_auxiliary_bundle();
   std::shared_ptr< burn_production_bundle > next_bundle();
   std::chrono::system_clock::time_point next_time_quantum( std::chrono::system_clock::time_point time );
   bool difficulty_met( const crypto::multihash& hash, uint64_t vhp_balance, uint256_t target );

   void fill_burn_parameters();
   uint64_t get_vhp_balance();
   uint32_t get_vhp_decimals();
   std::string get_vhp_symbol();
   contracts::pob::metadata get_metadata();
   contracts::pob::consensus_parameters get_consensus_parameters();

   // ASIO functions
   void produce( const boost::system::error_code& ec, std::shared_ptr< burn_production_bundle > pb );
   void query_production_data( const boost::system::error_code& ec );
   void query_auxiliary_data( const boost::system::error_code& ec );
};

} // koinos::block_production
