#pragma once

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <optional>

#include <boost/asio/steady_timer.hpp>

#include <koinos/block_production/block_producer.hpp>

namespace koinos::block_production {

using worker_group_type = std::pair< uint64_t, uint64_t >;
using nonce_type        = std::atomic< std::optional< uint64_t > >;
using hash_count_type   = std::atomic< uint64_t >;

class pow_producer final : public block_producer
{
public:
   pow_producer(
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client,
      std::size_t worker_groups
   );
   ~pow_producer();

protected:
   void produce();
   void display_hashrate( const boost::system::error_code& ec );

private:
   std::map< std::size_t, hash_count_type >      _worker_hashrate;
   std::vector< worker_group_type >              _worker_groups;
   std::mutex                                    _cv_mutex;
   std::condition_variable                       _cv;
   boost::asio::steady_timer                     _timer;

   uint32_t get_difficulty();
   void find_nonce(
      std::size_t worker_index,
      const protocol::block& block,
      uint32_t difficulty,
      uint64_t start,
      uint64_t end,
      std::shared_ptr< nonce_type > nonce_return
   );
   bool difficulty_met( const multihash& hash, uint32_t difficulty );
};

} // koinos::block_production
