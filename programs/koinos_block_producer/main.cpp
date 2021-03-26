#include <csignal>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <koinos/block_producer.hpp>
#include <koinos/exception.hpp>
#include <koinos/util.hpp>

using namespace boost;

#define HELP_OPTION    "help"
#define AMQP_OPTION    "amqp"
#define BASEDIR_OPTION "basedir"

int main( int argc, char** argv )
{
   try
   {
      program_options::options_description options;
      options.add_options()
         (HELP_OPTION   ",h", "Print this help message and exit.")
         (AMQP_OPTION   ",a", program_options::value< std::string >()->default_value( "amqp://guest:guest@localhost:5672/" ), "AMQP server URL")
         (BASEDIR_OPTION",d", program_options::value< std::string >()->default_value( koinos::get_default_base_directory().string() ), "Koinos base directory");

      program_options::variables_map args;
      program_options::store( program_options::parse_command_line( argc, argv, options ), args );

      if( args.count( HELP_OPTION ) )
      {
         std::cout << options << std::endl;
         return EXIT_FAILURE;
      }

      if( args.count( BASEDIR_OPTION ) )
      {
         auto basedir = filesystem::path{ args[ BASEDIR_OPTION ].as< std::string >() };
         if( basedir.is_relative() )
            basedir = filesystem::current_path() / basedir;

         koinos::initialize_logging( basedir, "block_producer/%3N.log" );
      }

      auto client = std::make_shared< koinos::mq::client >();
      auto ec = client->connect( args.at( AMQP_OPTION ).as< std::string >() );
      if ( ec != koinos::mq::error_code::success )
      {
         LOG(error) << "Unable to connect AMQP client";
         return EXIT_FAILURE;
      }

      boost::asio::io_context io_context;
      koinos::block_producer producer( io_context, client );
      LOG(info) << "Starting block producer...";
      producer.start();

      boost::asio::signal_set signals( io_context, SIGINT, SIGTERM );

      signals.async_wait( [&]( const boost::system::error_code& err, int num )
      {
         LOG(info) << "Caught signal, shutting down...";
         producer.stop();
      } );

      io_context.run();
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
      LOG(fatal) << "Unknown exception" << std::endl;
   }

   return EXIT_FAILURE;
}
