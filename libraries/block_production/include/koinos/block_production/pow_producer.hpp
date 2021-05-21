#pragma once

#include <atomic>
#include <condition_variable>
#include <optional>
#include <map>
#include <mutex>

#include <boost/asio/deadline_timer.hpp>

#include <koinos/block_production/block_producer.hpp>

namespace koinos::block_production {

using work_group = std::pair< uint64_t, uint64_t >;

class pow_producer : public block_producer
{
public:
   pow_producer(
      boost::asio::io_context& ioc,
      std::shared_ptr< mq::client > rpc_client,
      boost::asio::io_context& main_context,
      uint64_t work_groups
   );
   ~pow_producer();

protected:
   void produce();
   void show_hashrate( const boost::system::error_code& ec );

private:
   std::map< uint64_t, std::atomic< uint64_t > > _worker_hashes;
   std::vector< work_group >                     _work_groups;
   std::atomic< bool >                           _nonce_found;
   std::optional< uint64_t >                     _nonce;
   std::mutex                                    _nonce_mutex;
   std::condition_variable                       _cv;
   boost::asio::io_context&                      _main_context;
   boost::posix_time::milliseconds               _hashrate_interval;
   boost::asio::deadline_timer                   _timer;

   uint32_t get_difficulty();
   void find_nonce( uint64_t worker_index, const protocol::block& block, uint32_t difficulty, uint64_t start, uint64_t end );
   bool difficulty_met( const multihash& hash, uint32_t difficulty );
};

} // koinos::block_production
