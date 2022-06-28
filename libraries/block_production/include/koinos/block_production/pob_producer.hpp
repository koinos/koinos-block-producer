#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
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

using contract_id_type  = std::string;

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
      contract_id_type pob_contract_id,
      contract_id_type vhp_contract_id
   );
   ~pob_producer();

   virtual void on_block_accept( const protocol::block& b ) override;

protected:
   void commence() override;
   void halt() override;

private:
   boost::asio::system_timer                     _production_timer;
   const contract_id_type                        _pob_contract_id;
   const contract_id_type                        _vhp_contract_id;
   const uint32_t                                _get_metadata_entry_point = 0xfcf7a68f;
   const uint32_t                                _balance_of_entry_point = 0x5c721497;
   std::mutex                                    _time_quantum_mutex;
   std::chrono::system_clock::time_point         _last_time_quantum = std::chrono::system_clock::time_point{ std::chrono::milliseconds{ 0 } };

   std::chrono::system_clock::time_point next_time_quantum( std::chrono::system_clock::time_point time );
   void produce( const boost::system::error_code& ec );
   uint64_t get_vhp_balance();
   bool difficulty_met( const crypto::multihash& hash, uint64_t vhp_balance, uint256_t target );
   contracts::pob::metadata get_metadata();
};

} // koinos::block_production
