#include <csignal>
#include <filesystem>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>

#include <koinos/block_producer.hpp>
#include <koinos/exception.hpp>
#include <koinos/log.hpp>
#include <koinos/pack/classes.hpp>
#include <koinos/pack/rt/json.hpp>
#include <koinos/util.hpp>

#define HELP_OPTION        "help"
#define AMQP_OPTION        "amqp"
#define BASEDIR_OPTION     "basedir"
#define LOG_FILTER_OPTION  "log-filter"
#define INSTANCE_ID_OPTION "instance-id"

using namespace boost;
using namespace koinos;

constexpr uint32_t MAX_AMQP_CONNECT_SLEEP_MS = 30000;

int main( int argc, char** argv )
{
   try
   {
      program_options::options_description options;
      options.add_options()
         (HELP_OPTION       ",h", "Print this help message and exit.")
         (AMQP_OPTION       ",a", program_options::value< std::string >()->default_value( "amqp://guest:guest@localhost:5672/" ), "AMQP server URL")
         (BASEDIR_OPTION    ",d", program_options::value< std::string >()->default_value( get_default_base_directory().string() ), "Koinos base directory")
         (LOG_FILTER_OPTION ",l", program_options::value< std::string >()->default_value( "info" ), "The log filtering level")
         (INSTANCE_ID_OPTION",i", program_options::value< std::string >()->default_value( random_alphanumeric( 5 ) ), "An ID that uniquely identifies the instance");

      program_options::variables_map args;
      program_options::store( program_options::parse_command_line( argc, argv, options ), args );

      if( args.count( HELP_OPTION ) )
      {
         std::cout << options << std::endl;
         return EXIT_SUCCESS;
      }

      auto basedir = std::filesystem::path{ args[ BASEDIR_OPTION ].as< std::string >() };
      if( basedir.is_relative() )
         basedir = std::filesystem::current_path() / basedir;

      auto instance_id = args[ INSTANCE_ID_OPTION ].as< std::string >();
      auto level       = args[ LOG_FILTER_OPTION ].as< std::string >();

      initialize_logging( service::block_producer, instance_id, level, basedir / service::block_producer );

      auto client = std::make_shared< mq::client >();

      auto amqp_url = args[ AMQP_OPTION ].as< std::string >();
      uint32_t amqp_sleep_ms = 1000;

      LOG(info) << "Connecting AMQP client...";
      while ( true )
      {
         auto ec = client->connect( amqp_url );
         if ( ec == mq::error_code::success )
         {
            LOG(info) << "Connected client to AMQP server";
            break;
         }
         else
         {
            LOG(info) << "Failed, trying again in " << amqp_sleep_ms << " ms" ;
            std::this_thread::sleep_for( std::chrono::milliseconds( amqp_sleep_ms ) );
            amqp_sleep_ms = std::min( amqp_sleep_ms * 2, MAX_AMQP_CONNECT_SLEEP_MS );
         }
      }

      {
         LOG(info) << "Attempting to connect to chain...";
         pack::json j;
         pack::to_json( j, rpc::chain::chain_rpc_request{ rpc::chain::chain_reserved_request{} } );
         client->rpc( service::chain, j.dump() ).get();
         LOG(info) << "Established connection to chain";
      }

      {
         LOG(info) << "Attempting to connect to mempool...";
         pack::json j;
         pack::to_json( j, rpc::mempool::mempool_rpc_request{ rpc::mempool::mempool_reserved_request{} } );
         client->rpc( service::mempool, j.dump() ).get();
         LOG(info) << "Established connection to mempool";
      }

      boost::asio::io_context io_context;
      block_producer producer( io_context, client );
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
