#include <csignal>
#include <filesystem>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>

#include <yaml-cpp/yaml.h>

#include <koinos/block_producer.hpp>
#include <koinos/exception.hpp>
#include <koinos/log.hpp>
#include <koinos/pack/classes.hpp>
#include <koinos/pack/rt/json.hpp>
#include <koinos/util.hpp>

#define HELP_OPTION        "help"
#define BASEDIR_OPTION     "basedir"
#define AMQP_OPTION        "amqp"
#define AMQP_DEFAULT       "amqp://guest:guest@localhost:5672/"
#define LOG_LEVEL_OPTION       "log-level"
#define LOG_LEVEL_DEFAULT      "info"
#define INSTANCE_ID_OPTION     "instance-id"

using namespace boost;
using namespace koinos;

constexpr uint32_t MAX_AMQP_CONNECT_SLEEP_MS = 30000;

template< typename T >
T get_option(
   std::string key,
   T default_value,
   const program_options::variables_map& cli_args,
   const YAML::Node& service_config = YAML::Node(),
   const YAML::Node& global_config = YAML::Node() )
{
   if ( cli_args.count( key ) )
      return cli_args[ key ].as< T >();

   if ( service_config && service_config[ key ] )
      return service_config[ key ].as< T >();

   if ( global_config && global_config[ key ] )
      return global_config[ key ].as< T >();

   return std::move( default_value );
}

int main( int argc, char** argv )
{
   try
   {
      program_options::options_description options;
      options.add_options()
         (HELP_OPTION       ",h", "Print this help message and exit.")
         (BASEDIR_OPTION    ",d", program_options::value< std::string >()->default_value( get_default_base_directory().string() ), "Koinos base directory")
         (AMQP_OPTION       ",a", program_options::value< std::string >(), "AMQP server URL")
         (LOG_LEVEL_OPTION  ",l", program_options::value< std::string >(), "The log filtering level")
         (INSTANCE_ID_OPTION",i", program_options::value< std::string >(), "An ID that uniquely identifies the instance");

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

      YAML::Node config;
      YAML::Node global_config;
      YAML::Node block_producer_config;

      auto yaml_config = basedir / "config.yml";
      if ( !std::filesystem::exists( yaml_config ) )
      {
         yaml_config = basedir / "config.yaml";
      }

      if ( std::filesystem::exists( yaml_config ) )
      {
         config = YAML::LoadFile( yaml_config );
         global_config = config[ "global" ];
         block_producer_config = config[ service::block_producer ];
      }

      auto amqp_url    = get_option< std::string >( AMQP_OPTION, AMQP_DEFAULT, args, block_producer_config, global_config );
      auto log_level   = get_option< std::string >( LOG_LEVEL_OPTION, LOG_LEVEL_DEFAULT, args, block_producer_config, global_config );
      auto instance_id = get_option< std::string >( INSTANCE_ID_OPTION, random_alphanumeric( 5 ), args, block_producer_config, global_config );

      initialize_logging( service::block_producer, instance_id, log_level, basedir / service::block_producer );

      if ( !config )
      {
         LOG(warning) << "Could not find config (config.yml or config.yaml expected). Using default values";
      }

      auto client = std::make_shared< mq::client >();

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
