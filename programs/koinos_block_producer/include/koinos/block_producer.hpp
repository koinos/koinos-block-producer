#include <koinos/mq/client.hpp>

#include <memory>

namespace koinos {

namespace detail{ struct block_producer_impl; }

struct block_producer
{
   block_producer( std::shared_ptr< mq::client > );
   ~block_producer();

   void start();
   void stop();

   private:
      std::unique_ptr< detail::block_producer_impl > _my;
};

} // koinos
