#pragma once

#include <boost/asio/steady_timer.hpp>

#include <koinos/block_production/block_producer.hpp>

namespace koinos::block_production {

class federated_producer : public block_producer
{
public:
   federated_producer(
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client
   );
   ~federated_producer();

protected:
   void produce( const boost::system::error_code& ec );

   boost::asio::steady_timer _timer;
};

} // koinos::block_production
