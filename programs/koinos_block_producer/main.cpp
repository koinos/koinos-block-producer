#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>

#include <yaml-cpp/yaml.h>

#include <koinos/block_production/federated_producer.hpp>
#include <koinos/block_production/pow_producer.hpp>
#include <koinos/exception.hpp>
#include <koinos/log.hpp>
#include <koinos/mq/request_handler.hpp>
#include <koinos/broadcast/broadcast.pb.h>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/rpc/mempool/mempool_rpc.pb.h>
#include <koinos/util.hpp>

#define FEDERATED_ALGORITHM                "federated"
#define POW_ALGORITHM                      "pow"

#define HELP_OPTION                        "help"
#define BASEDIR_OPTION                     "basedir"
#define AMQP_OPTION                        "amqp"
#define AMQP_DEFAULT                       "amqp://guest:guest@localhost:5672/"
#define LOG_LEVEL_OPTION                   "log-level"
#define LOG_LEVEL_DEFAULT                  "info"
#define INSTANCE_ID_OPTION                 "instance-id"
#define ALGORITHM_OPTION                   "algorithm"
#define JOBS_OPTION                        "jobs"
#define WORK_GROUPS_OPTION                 "work-groups"
#define PRIVATE_KEY_FILE_OPTION            "private-key-file"
#define PRIVATE_KEY_FILE_DEFAULT           "private.key"
#define POW_CONTRACT_ID_OPTION             "pow-contract-id"
#define STALE_PRODUCTION_THRESHOLD_OPTION  "stale-production-threshold"
#define STALE_PRODUCTION_THRESHOLD_DEFAULT int64_t( 1800 )

using namespace boost;
using namespace koinos;

using work_guard_type = boost::asio::executor_work_guard< boost::asio::io_context::executor_type >;

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
         (HELP_OPTION                      ",h", "Print this help message and exit.")
         (BASEDIR_OPTION                   ",d",
            program_options::value< std::string >()->default_value( get_default_base_directory().string() ), "Koinos base directory")
         (AMQP_OPTION                      ",a", program_options::value< std::string >(), "AMQP server URL")
         (LOG_LEVEL_OPTION                 ",l", program_options::value< std::string >(), "The log filtering level")
         (INSTANCE_ID_OPTION               ",i", program_options::value< std::string >(), "An ID that uniquely identifies the instance")
         (ALGORITHM_OPTION                 ",g", program_options::value< std::string >(), "The consensus algorithm to use")
         (JOBS_OPTION                      ",j", program_options::value< uint64_t    >(), "The number of worker jobs")
         (WORK_GROUPS_OPTION               ",w", program_options::value< uint64_t    >(), "The number of worker groups")
         (PRIVATE_KEY_FILE_OPTION          ",p", program_options::value< std::string >(), "The private key file")
         (POW_CONTRACT_ID_OPTION           ",c", program_options::value< std::string >(), "The PoW contract ID")
         (STALE_PRODUCTION_THRESHOLD_OPTION",s",
            program_options::value< int64_t >(), "The distance of time in seconds from head where production should begin (-1 to disable)");

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
      auto algorithm   = get_option< std::string >( ALGORITHM_OPTION, FEDERATED_ALGORITHM, args, block_producer_config, global_config );
      auto jobs        = get_option< uint64_t    >( JOBS_OPTION, std::thread::hardware_concurrency(), args, block_producer_config, global_config );
      auto work_groups = get_option< uint64_t    >( WORK_GROUPS_OPTION, jobs, args, block_producer_config, global_config );
      auto pk_file     = get_option< std::string >( PRIVATE_KEY_FILE_OPTION, PRIVATE_KEY_FILE_DEFAULT, args, block_producer_config, global_config );
      auto pow_id      = get_option< std::string >( POW_CONTRACT_ID_OPTION, "", args, block_producer_config, global_config );

      auto production_threshold = get_option< int64_t >(
         STALE_PRODUCTION_THRESHOLD_OPTION,
         STALE_PRODUCTION_THRESHOLD_DEFAULT,
         args,
         block_producer_config,
         global_config
      );

      initialize_logging( service::block_producer, instance_id, log_level, basedir / service::block_producer );

      KOINOS_ASSERT(
         production_threshold <= std::numeric_limits< int64_t >::max() / 1000,
         koinos::exception,
         "Stale block production threshold would overflow, maximum value: ${v}",
         ("v", std::numeric_limits< int64_t >::max() / 1000)
      );

      KOINOS_ASSERT( jobs > 0, koinos::exception, "Jobs must be greater than 0" );

      if ( config.IsNull() )
      {
         LOG(warning) << "Could not find config (config.yml or config.yaml expected), using default values";
      }

      std::filesystem::path private_key_file{ pk_file };
      if ( private_key_file.is_relative() )
         private_key_file = basedir / service::block_producer / private_key_file;

      KOINOS_ASSERT(
         std::filesystem::exists( private_key_file ),
         koinos::exception,
         "Unable to find private key file at: ${loc}", ("loc", private_key_file.string())
      );

      std::ifstream ifs( private_key_file );
      std::string private_key_wif( ( std::istreambuf_iterator< char >( ifs ) ), ( std::istreambuf_iterator< char >() ) );
      crypto::private_key signing_key = crypto::private_key::from_wif( private_key_wif );

      LOG(info) << "Public address: " << to_hex( signing_key.get_public_key().to_address_bytes() );

      auto client = std::make_shared< mq::client >();

      LOG(info) << "Connecting AMQP client...";
      auto ec = client->connect( amqp_url );
      if ( ec != mq::error_code::success )
      {
         LOG(info) << "Unable to connect to AMQP server" ;
         exit( EXIT_FAILURE );
      }
      LOG(info) << "Connected client to AMQP server";

      {
         LOG(info) << "Attempting to connect to chain...";
         rpc::chain::chain_request req;
         req.mutable_reserved();
         std::string s;
         req.SerializeToString( &s );
         client->rpc( service::chain, s ).get();
         LOG(info) << "Established connection to chain";
      }

      {
         LOG(info) << "Attempting to connect to mempool...";
         rpc::mempool::mempool_request req;
         req.mutable_reserved();
         std::string s;
         req.SerializeToString( &s );
         client->rpc( service::mempool, s ).get();
         LOG(info) << "Established connection to mempool";
      }

      boost::asio::io_context production_context, main_context;
      std::unique_ptr< block_production::block_producer > producer;

      if ( algorithm == FEDERATED_ALGORITHM )
      {
         LOG(info) << "Using " << FEDERATED_ALGORITHM << " algorithm";
         producer = std::make_unique< block_production::federated_producer >(
            signing_key,
            main_context,
            production_context,
            client,
            production_threshold
         );
      }
      else if ( algorithm == POW_ALGORITHM )
      {
         LOG(info) << "Using " << POW_ALGORITHM << " algorithm";

         producer = std::make_unique< block_production::pow_producer >(
            signing_key,
            main_context,
            production_context,
            client,
            production_threshold,
            pow_id,
            work_groups
         );

         LOG(info) << "Using " << work_groups << " work groups";
      }
      else
      {
         LOG(error) << "Unrecognized consensus algorithm";
         exit( EXIT_FAILURE );
      }

      mq::request_handler reqhandler;

      ec = reqhandler.add_broadcast_handler(
         "koinos.block.accept",
         [&]( const std::string& msg )
         {
            try
            {
               broadcast::block_accepted bam;
               bam.ParseFromString( msg );
               producer->on_block_accept( bam.block() );
            }
            catch( const boost::exception& e )
            {
               LOG(warning) << "Error handling block broadcast: " << boost::diagnostic_information( e );
            }
            catch( const std::exception& e )
            {
               LOG(warning) << "Error handling block broadcast: " << e.what();
            }
         }
      );

      if ( ec != mq::error_code::success )
      {
         LOG(error) << "Unable to register block broadcast handler";
         exit( EXIT_FAILURE );
      }

      LOG(info) << "Connecting AMQP request handler...";
      ec = reqhandler.connect( amqp_url );
      if ( ec != mq::error_code::success )
      {
         LOG(info) << "Unable to connect to AMQP request handler" ;
         exit( EXIT_FAILURE );
      }
      LOG(info) << "Connected client to AMQP server";

      reqhandler.start();

      LOG(info) << "Using " << jobs << " jobs";
      LOG(info) << "Starting block producer...";

      work_guard_type production_work_guard( production_context.get_executor() );
      work_guard_type main_work_guard( main_context.get_executor() );

      boost::asio::signal_set signals( main_context, SIGINT, SIGTERM );

      signals.async_wait( [&]( const boost::system::error_code& err, int num )
      {
         LOG(info) << "Caught signal, shutting down...";
         production_context.stop();
         main_context.stop();
         reqhandler.stop();
      } );

      std::vector< std::thread > threads;
      for ( std::size_t i = 0; i < jobs + 1; i++ )
         threads.emplace_back( [&]() { production_context.run(); } );

      main_context.run();

      for ( auto& t : threads )
         t.join();
   }
   catch ( const std::exception& e )
   {
      LOG(fatal) << e.what() << std::endl;
   }
   catch ( const boost::exception& e )
   {
      LOG(fatal) << boost::diagnostic_information( e ) << std::endl;
   }
   catch ( ... )
   {
      LOG(fatal) << "Unknown exception" << std::endl;
   }

   return EXIT_FAILURE;
}
