#include <block_producer.hpp>

#include <thread>

namespace detail {

struct block_producer_impl
{
   block_producer_impl() = default;
   ~block_producer_impl();

   void start();
   void stop();

   void main_loop();

   bool        _running;
   std::unique_ptr< std::thread > _main_thread;
};

block_producer_impl::~block_producer_impl()
{
   stop();
}

void block_producer_impl::start()
{
   if ( !_running )
   {
      _running = true;
      _main_thread = std::make_unique< std::thread >( [&]()
      {
         main_loop();
      } );
   }
}

void block_producer_impl::stop()
{
   if ( _running )
   {
      _running = false;
      _main_thread->join();
   }
}

void block_producer_impl::main_loop()
{
   while ( _running )
   {
      std::this_thread::sleep_for( std::chrono::seconds(1) );
   }
}

} // detail

block_producer::block_producer() :
   _my( std::make_unique< detail::block_producer_impl >() )
{}

block_producer::~block_producer() {}

void block_producer::start()
{
   _my->start();
}

void block_producer::stop()
{
   _my->stop();
}
