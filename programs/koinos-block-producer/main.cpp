
#include <koinos/block_producer.hpp>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>

#include <koinos/exception.hpp>

#include <csignal>
#include <iostream>

namespace bpo = boost::program_options;

int main( int argc, char** argv )
{
   try
   {
      bpo::options_description options;
      options.add_options()
         ("help,h", "Print this help message and exit.")
         ("amqp,a", bpo::value<std::string>()->default_value("amqp://guest:guest@localhost:5672/"), "AMQP server URL");

      bpo::variables_map args;
      bpo::store( bpo::parse_command_line( argc, argv, options ), args );

      if( args.count( "help" ) )
      {
         std::cout << options << "\n";
         return EXIT_FAILURE;
      }

      auto client = std::make_shared< koinos::mq::client >();
      auto ec = client->connect( args.at( "amqp" ).as< std::string >() );
      if ( ec != koinos::mq::error_code::success )
      {
         LOG(error) << "Unable to connect amqp client";
         return EXIT_FAILURE;
      }

      koinos::block_producer producer( client );
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
