#pragma once

#include <atomic>

#include <boost/asio/steady_timer.hpp>

#include <koinos/block_production/block_producer.hpp>

namespace koinos::block_production {

class federated_producer: public block_producer
{
public:
  federated_producer( crypto::private_key signing_key,
                      boost::asio::io_context& main_context,
                      boost::asio::io_context& production_context,
                      std::shared_ptr< mq::client > rpc_client,
                      uint64_t resources_lower_bound,
                      uint64_t resources_upper_bound,
                      uint64_t max_inclusion_attempts,
                      bool gossip_production,
                      const std::vector< std::string >& approved_proposals );
  ~federated_producer();

protected:
  void commence() override;
  void halt() override;

private:
  void produce( const boost::system::error_code& ec );

  boost::asio::steady_timer _timer;
};

} // namespace koinos::block_production
