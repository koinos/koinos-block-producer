#pragma once

#include <atomic>

#include <boost/asio/steady_timer.hpp>

#include <koinos/block_production/block_producer.hpp>

namespace koinos::block_production {

class federated_producer : public block_producer
{
public:
   federated_producer(
      crypto::private_key signing_key,
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client,
      int64_t production_threshold,
      uint64_t resources_lower_bound,
      uint64_t resources_upper_bound,
      uint64_t max_inclusion_attempts,
      bool gossip_production
   );
   ~federated_producer();

protected:
   void commence() override;
   void halt() override;

private:
   void produce( const boost::system::error_code& ec );

   boost::asio::steady_timer _timer;
};

} // koinos::block_production
