
#include <block_producer.hpp>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>

#include <koinos/exception.hpp>

#include <csignal>
#include <iostream>

int main( int argc, char** argv )
{
   try
   {
      boost::program_options::options_description options;
      options.add_options()
         ("help,h", "Print this help message and exit.");

      boost::program_options::variables_map args;
      boost::program_options::store( boost::program_options::parse_command_line( argc, argv, options ), args );

      if( args.count( "help" ) )
      {
         std::cout << options << "\n";
         return EXIT_FAILURE;
      }

      block_producer producer;
      LOG(info) << "Starting block producer...";
      producer.start();

      boost::asio::io_service io_service;
      boost::asio::signal_set signals( io_service, SIGINT, SIGTERM );

      signals.async_wait( [&]( const boost::system::error_code& err, int num )
      {
         LOG(info) << "Caught signal, shutting down...";
         producer.stop();
      } );

      io_service.run();
   }
   catch ( const boost::exception& e )
   {
      LOG(fatal) << boost::diagnostic_information( e ) << std::endl;
   }
   catch ( const std::exception& e )
   {
      LOG(fatal) << e.what() << std::endl;
   }
   catch ( ... )
   {
      LOG(fatal) << "unknown exception" << std::endl;
   }

   return EXIT_FAILURE;
}
