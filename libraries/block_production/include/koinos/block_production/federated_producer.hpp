#pragma once

#include <boost/asio/deadline_timer.hpp>

#include <koinos/block_production/block_producer.hpp>

namespace koinos::block_production {

class federated_producer : public block_producer
{
public:
   federated_producer( boost::asio::io_context& ioc, std::shared_ptr< mq::client > rpc_client );
   ~federated_producer();

protected:
   void produce( const boost::system::error_code& ec );

   boost::posix_time::milliseconds  _production_interval;
   boost::asio::deadline_timer      _timer;
};

} // koinos::block_production
