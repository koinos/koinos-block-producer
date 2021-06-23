#pragma once

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <optional>

#include <boost/asio/steady_timer.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <koinos/block_production/block_producer.hpp>
#include <koinos/pack/classes.hpp>

namespace koinos::block_production {

using boost::multiprecision::uint512_t;
using boost::multiprecision::uint256_t;

using worker_group_type = std::pair< uint256_t, uint256_t >;
using hash_count_type   = std::atomic< uint64_t >;

class pow_producer : public block_producer
{
public:
   pow_producer(
      crypto::private_key signing_key,
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client,
      std::size_t worker_groups
   );
   ~pow_producer();

   virtual void on_block_accept( const protocol::block& b ) override;

protected:
   void produce( const boost::system::error_code& ec );
   void display_hashrate( const boost::system::error_code& ec );

private:
   std::map< std::size_t, hash_count_type >      _worker_hashrate;
   std::vector< worker_group_type >              _worker_groups;
   std::mutex                                    _cv_mutex;
   std::condition_variable                       _cv;
   boost::asio::steady_timer                     _update_timer;
   block_height_type                             _last_known_height;
   boost::asio::steady_timer                     _error_timer;
   std::atomic< std::chrono::seconds >           _error_wait_time = std::chrono::seconds( 5 );
   std::atomic< bool >                           _hashing;

   void find_nonce(
      std::size_t worker_index,
      const protocol::block& block,
      uint256_t difficulty,
      uint256_t start,
      uint256_t end,
      std::shared_ptr< std::optional< uint256_t > > nonce,
      std::shared_ptr< std::atomic< bool > > done
   );
   bool difficulty_met( const multihash& hash, uint256_t difficulty );
   uint256_t get_difficulty();
};

} // koinos::block_production
