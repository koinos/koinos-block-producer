#pragma once

#include <atomic>
#include <memory>
#include <variant>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/broadcast/broadcast.pb.h>
#include <koinos/exception.hpp>
#include <koinos/mq/client.hpp>
#include <koinos/protocol/protocol.pb.h>

namespace koinos::block_production {

KOINOS_DECLARE_EXCEPTION( block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( rpc_failure, block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( timestamp_overflow, block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( nonce_failure, block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( deserialization_failure, block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( out_of_bounds_failure, block_production_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( invalid_parameter, block_production_exception );

class block_producer
{
public:
   block_producer(
      crypto::private_key signing_key,
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client,
      uint64_t resources_lower_bound,
      uint64_t resources_upper_bound,
      uint64_t max_inclusion_attempts,
      bool gossip_production,
      const std::vector< std::string >& approved_proposals
   );
   virtual ~block_producer();

   virtual void on_gossip_status( const broadcast::gossip_status& gs );
   virtual void on_block_accept( const broadcast::block_accepted& bam );

protected:
   protocol::block next_block( std::string signer );
   protocol::block next_block();

   // Submits a block, returns true if block needs to be resubmitted
   bool submit_block( protocol::block& b );

   virtual void commence() = 0;
   virtual void halt()     = 0;

   boost::asio::io_context&          _main_context;
   boost::asio::io_context&          _production_context;
   boost::asio::signal_set           _signals;
   std::shared_ptr< mq::client >     _rpc_client;
   const crypto::private_key         _signing_key;
   std::atomic< int64_t >            _last_block_time = 0;
   std::atomic< bool >               _halted = true;
   const uint64_t                    _resources_lower_bound;
   const uint64_t                    _resources_upper_bound;
   const uint64_t                    _max_inclusion_attempts;
   const bool                        _gossip_production;
   const std::vector< std::string >& _approved_proposals;

private:
   void on_run( const boost::system::error_code& ec );
   void fill_block( protocol::block& b );
   void trim_block( protocol::block& b, const std::string& trx_id );
   void set_merkle_roots( protocol::block&, crypto::multicodec code, crypto::digest_size size = crypto::digest_size( 0 ) );
   uint64_t now();
};

} // koinos::block_production
