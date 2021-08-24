#pragma once

#include <atomic>
#include <memory>

#include <boost/asio/io_context.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/exception.hpp>
#include <koinos/mq/client.hpp>
#include <koinos/protocol/protocol.pb.h>

struct empty_hash_t {};
using passive_hash_target = std::variant< const google::protobuf::Message*, const std::string*, empty_hash_t >;

namespace koinos::crypto {
   inline multihash hash( multicodec code, const passive_hash_target& t )
   {
      multihash mh;

      std::visit(
         koinos::overloaded{
            [&]( const google::protobuf::Message* m )
            {
               std::string s;
               m->SerializeToString( &s );

               mh = hash( code, s );
            },
            [&]( const std::string* s )
            {
               mh = hash( code, *s );
            },
            [&]( const empty_hash_t& )
            {
               mh = multihash::empty( code );
            },
            [&]( auto )
            {
               mh = multihash::zero( code );
            }
         },
         t
      );

      return mh;
   }
}

namespace koinos::block_production {

class block_producer
{
public:
   block_producer(
      crypto::private_key signing_key,
      boost::asio::io_context& main_context,
      boost::asio::io_context& production_context,
      std::shared_ptr< mq::client > rpc_client,
      int64_t production_threshold
   );
   virtual ~block_producer();

   virtual void on_block_accept( const protocol::block& b );

protected:
   protocol::block next_block();
   void fill_block( protocol::block& b );
   void submit_block( protocol::block& b );

   virtual void commence() = 0;
   virtual void halt()     = 0;

   boost::asio::io_context&         _main_context;
   boost::asio::io_context&         _production_context;
   std::shared_ptr< mq::client >    _rpc_client;
   const crypto::private_key        _signing_key;
   std::atomic< uint64_t >          _last_block_time = 0;
   std::atomic< bool >              _halted = true;
   const int64_t                    _production_threshold;

private:
   void on_run( const boost::system::error_code& ec );
   void set_merkle_roots( protocol::block& block, crypto::multicodec code, uint64_t size = 0 );
   uint64_t now();
};

} // koinos::block_production
