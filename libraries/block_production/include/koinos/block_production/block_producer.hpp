#pragma once

#include <atomic>
#include <memory>
#include <variant>

#include <boost/asio/io_context.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/exception.hpp>
#include <koinos/mq/client.hpp>
#include <koinos/protocol/protocol.pb.h>

namespace koinos::block_production {

KOINOS_DECLARE_EXCEPTION( block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( rpc_failure, block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( timestamp_overflow, block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( nonce_failure, block_production_exception );

class block_producer
{
public:
   block_producer(
      crypto::private_key signing_key,
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client,
      int64_t production_threshold,
      uint64_t resources_lower_bound,
      uint64_t resources_upper_bound,
      uint64_t max_inclusion_attempts
   );
   virtual ~block_producer();

   virtual void on_block_accept( const protocol::block& b );

protected:
   protocol::block next_block();

   // Submits a block, returns true if block needs to be resubmitted
   bool submit_block( protocol::block& b );

   virtual void commence() = 0;
   virtual void halt()     = 0;

   boost::asio::io_context&         _main_context;
   boost::asio::io_context&         _production_context;
   std::shared_ptr< mq::client >    _rpc_client;
   const crypto::private_key        _signing_key;
   std::atomic< int64_t >           _last_block_time = 0;
   std::atomic< bool >              _halted = true;
   const int64_t                    _production_threshold;
   const uint64_t                   _resources_lower_bound;
   const uint64_t                   _resources_upper_bound;
   const uint64_t                   _max_inclusion_attempts;

private:
   void on_run( const boost::system::error_code& ec );
   void fill_block( protocol::block& b );
   void trim_block( protocol::block& b, const std::string& trx_id );
   void set_merkle_roots( protocol::block&, crypto::multicodec code, crypto::digest_size size = crypto::digest_size( 0 ) );
   uint64_t now();
};

} // koinos::block_production
