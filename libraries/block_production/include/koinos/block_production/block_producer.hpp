#pragma once

#include <memory>

#include <boost/asio/io_context.hpp>

#include <koinos/mq/client.hpp>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/pack/classes.hpp>

namespace koinos::block_production {

class block_producer
{
public:
   block_producer( boost::asio::io_context& ioc, std::shared_ptr< mq::client > rpc_client );
   virtual ~block_producer();

protected:
   protocol::block next_block();
   void fill_block( protocol::block& b );
   void submit_block( protocol::block& b );

   boost::asio::io_context&         _io_context;
   std::shared_ptr< mq::client >    _rpc_client;
   crypto::private_key              _signing_key;

private:
   void set_merkle_roots( protocol::block& block, uint64_t code, uint64_t size = 0 );
   timestamp_type now();
};

} // koinos::block_production
