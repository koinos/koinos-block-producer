#pragma once

#include <memory>

#include <boost/asio/io_context.hpp>

#include <koinos/mq/client.hpp>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/pack/classes.hpp>
#include <koinos/exception.hpp>

namespace koinos::block_production {

class block_producer
{
public:
   block_producer(
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client
   );
   virtual ~block_producer();

   virtual void on_block_accept( const protocol::block& b );

protected:
   protocol::block next_block();
   void fill_block( protocol::block& b );
   void submit_block( protocol::block& b );

   boost::asio::io_context&         _main_context;
   boost::asio::io_context&         _production_context;
   std::shared_ptr< mq::client >    _rpc_client;
   crypto::private_key              _signing_key;
   timestamp_type                   _last_block_time;

private:
   void set_merkle_roots( protocol::block& block, uint64_t code, uint64_t size = 0 );
   timestamp_type now();
};

} // koinos::block_production
