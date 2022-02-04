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
#include <koinos/util/base58.hpp>
#include <koinos/util/conversion.hpp>
#include <koinos/util/options.hpp>
#include <koinos/util/random.hpp>
#include <koinos/util/services.hpp>

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
#define GOSSIP_PRODUCTION_OPTION           "gossip-production"
#define GOSSIP_PRODUCTION_DEFAULT          bool( false )
#define RESOURCES_LOWER_BOUND_OPTION       "resources-lower-bound"
#define RESOURCES_LOWER_BOUND_DEFAULT      uint64_t( 75 )
#define RESOURCES_UPPER_BOUND_OPTION       "resources-upper-bound"
#define RESOURCES_UPPER_BOUND_DEFAULT      uint64_t( 90 )
#define MAX_INCLUSION_ATTEMPTS_OPTION      "max-inclusion-attempts"
#define MAX_INCLUSION_ATTEMPTS_DEFAULT     uint64_t( 100 )

KOINOS_DECLARE_EXCEPTION( service_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( invalid_argument, service_exception );

using namespace boost;
using namespace koinos;

int main( int argc, char** argv )
{
   try
   {
      program_options::options_description options;
      options.add_options()
         (HELP_OPTION                      ",h", "Print this help message and exit.")
         (BASEDIR_OPTION                   ",d",
            program_options::value< std::string >()->default_value( util::get_default_base_directory().string() ), "Koinos base directory")
         (AMQP_OPTION                      ",a", program_options::value< std::string >(), "AMQP server URL")
         (LOG_LEVEL_OPTION                 ",l", program_options::value< std::string >(), "The log filtering level")
         (INSTANCE_ID_OPTION               ",i", program_options::value< std::string >(), "An ID that uniquely identifies the instance")
         (ALGORITHM_OPTION                 ",g", program_options::value< std::string >(), "The consensus algorithm to use")
         (JOBS_OPTION                      ",j", program_options::value< uint64_t    >(), "The number of worker jobs")
         (WORK_GROUPS_OPTION               ",w", program_options::value< uint64_t    >(), "The number of worker groups")
         (PRIVATE_KEY_FILE_OPTION          ",p", program_options::value< std::string >(), "The private key file")
         (POW_CONTRACT_ID_OPTION           ",c", program_options::value< std::string >(), "The PoW contract ID")
         (MAX_INCLUSION_ATTEMPTS_OPTION    ",m", program_options::value< uint64_t    >(), "The maximum transaction inclusion attempts per block")
         (RESOURCES_LOWER_BOUND_OPTION     ",z", program_options::value< uint64_t    >(), "The resource utilization lower bound as a percentage")
         (RESOURCES_UPPER_BOUND_OPTION     ",x", program_options::value< uint64_t    >(), "The resource utilization upper bound as a percentage")
         (GOSSIP_PRODUCTION_OPTION         ",G",                                          "Use p2p gossip status to determine block production");

      program_options::variables_map args;
      program_options::store( program_options::parse_command_line( argc, argv, options ), args );

      if ( args.count( HELP_OPTION ) )
      {
         std::cout << options << std::endl;
         return EXIT_SUCCESS;
      }

      auto basedir = std::filesystem::path{ args[ BASEDIR_OPTION ].as< std::string >() };
      if ( basedir.is_relative() )
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
         block_producer_config = config[ util::service::block_producer ];
      }

      auto amqp_url     = util::get_option< std::string >( AMQP_OPTION, AMQP_DEFAULT, args, block_producer_config, global_config );
      auto log_level    = util::get_option< std::string >( LOG_LEVEL_OPTION, LOG_LEVEL_DEFAULT, args, block_producer_config, global_config );
      auto instance_id  = util::get_option< std::string >( INSTANCE_ID_OPTION, util::random_alphanumeric( 5 ), args, block_producer_config, global_config );
      auto algorithm    = util::get_option< std::string >( ALGORITHM_OPTION, FEDERATED_ALGORITHM, args, block_producer_config, global_config );
      auto jobs         = util::get_option< uint64_t    >( JOBS_OPTION, std::thread::hardware_concurrency(), args, block_producer_config, global_config );
      auto work_groups  = util::get_option< uint64_t    >( WORK_GROUPS_OPTION, jobs, args, block_producer_config, global_config );
      auto pk_file      = util::get_option< std::string >( PRIVATE_KEY_FILE_OPTION, PRIVATE_KEY_FILE_DEFAULT, args, block_producer_config, global_config );
      auto pow_id       = util::get_option< std::string >( POW_CONTRACT_ID_OPTION, "", args, block_producer_config, global_config );
      auto rcs_lbound   = util::get_option< uint64_t    >( RESOURCES_LOWER_BOUND_OPTION, RESOURCES_LOWER_BOUND_DEFAULT, args, block_producer_config, global_config );
      auto rcs_ubound        = util::get_option< uint64_t    >( RESOURCES_UPPER_BOUND_OPTION, RESOURCES_UPPER_BOUND_DEFAULT, args, block_producer_config, global_config );
      auto max_attempts      = util::get_option< uint64_t    >( MAX_INCLUSION_ATTEMPTS_OPTION, MAX_INCLUSION_ATTEMPTS_DEFAULT, args, block_producer_config, global_config );
      auto gossip_production = util::get_option< bool        >( GOSSIP_PRODUCTION_OPTION, GOSSIP_PRODUCTION_DEFAULT, args, block_producer_config, global_config );

      initialize_logging( util::service::block_producer, instance_id, log_level, basedir / util::service::block_producer );

      KOINOS_ASSERT( rcs_lbound >= 0 && rcs_lbound <= 100, invalid_argument, "resource lower bound out of range [0..100]" );
      KOINOS_ASSERT( rcs_ubound >= 0 && rcs_ubound <= 100, invalid_argument, "resource upper bound out of range [0..100]" );

      KOINOS_ASSERT( jobs > 0, invalid_argument, "jobs must be greater than 0" );

      if ( config.IsNull() )
      {
         LOG(warning) << "Could not find config (config.yml or config.yaml expected), using default values";
      }

      std::filesystem::path private_key_file{ pk_file };
      if ( private_key_file.is_relative() )
         private_key_file = basedir / util::service::block_producer / private_key_file;

      KOINOS_ASSERT(
         std::filesystem::exists( private_key_file ),
         invalid_argument,
         "unable to find private key file at: ${loc}", ("loc", private_key_file)
      );

      crypto::private_key signing_key;

      try
      {
         std::ifstream ifs( private_key_file );
         std::string private_key_wif;
         std::getline( ifs, private_key_wif );
         signing_key = crypto::private_key::from_wif( private_key_wif );
      }
      catch ( const std::exception& e )
      {
         KOINOS_THROW( invalid_argument, "unable to parse private key file at ${f}, ${r}", ("f", private_key_file)("r", e.what()) );
      }

      LOG(info) << "Public address: " << util::to_base58( signing_key.get_public_key().to_address_bytes() );
      LOG(info) << "Block resource utilization lower bound: " << rcs_lbound << "%, upper bound: " << rcs_ubound << "%";
      LOG(info) << "Maximum transaction inclusion attempts per block: " << max_attempts;

      auto client = std::make_shared< mq::client >();

      LOG(info) << "Connecting AMQP client...";
      client->connect( amqp_url );
      LOG(info) << "Established AMQP client connection to the server";

      LOG(info) << "Attempting to connect to chain...";
      rpc::chain::chain_request creq;
      creq.mutable_reserved();
      client->rpc( util::service::chain, creq.SerializeAsString() ).get();
      LOG(info) << "Established connection to chain";

      LOG(info) << "Attempting to connect to mempool...";
      rpc::mempool::mempool_request mreq;
      mreq.mutable_reserved();
      client->rpc( util::service::mempool, mreq.SerializeAsString() ).get();
      LOG(info) << "Established connection to mempool";

      asio::io_context work_context, main_context;
      std::unique_ptr< block_production::block_producer > producer;

      if ( algorithm == FEDERATED_ALGORITHM )
      {
         LOG(info) << "Using " << FEDERATED_ALGORITHM << " algorithm";
         producer = std::make_unique< block_production::federated_producer >(
            signing_key,
            main_context,
            work_context,
            client,
            rcs_lbound,
            rcs_ubound,
            max_attempts,
            gossip_production
         );
      }
      else if ( algorithm == POW_ALGORITHM )
      {
         LOG(info) << "Using " << POW_ALGORITHM << " algorithm";
         auto pow_address = util::from_base58< std::string >( pow_id );

         producer = std::make_unique< block_production::pow_producer >(
            signing_key,
            main_context,
            work_context,
            client,
            rcs_lbound,
            rcs_ubound,
            max_attempts,
            gossip_production,
            pow_address,
            work_groups
         );

         LOG(info) << "Using " << work_groups << " work groups";
      }
      else
      {
         KOINOS_THROW( invalid_argument, "unrecognized consensus algorithm" );
      }

      mq::request_handler reqhandler( work_context );

      reqhandler.add_broadcast_handler(
         "koinos.block.accept",
         [&]( const std::string& msg )
         {
            try
            {
               broadcast::block_accepted bam;
               bam.ParseFromString( msg );
               producer->on_block_accept( bam.block() );
            }
            catch ( const boost::exception& e )
            {
               LOG(warning) << "Error handling block broadcast: " << boost::diagnostic_information( e );
            }
            catch ( const std::exception& e )
            {
               LOG(warning) << "Error handling block broadcast: " << e.what();
            }
         }
      );

      reqhandler.add_broadcast_handler(
         "koinos.gossip.status",
         [&]( const std::string& msg )
         {
            try
            {
               broadcast::gossip_status gsm;
               gsm.ParseFromString( msg );
               producer->on_gossip_status( gsm );
            }
            catch ( const boost::exception& e )
            {
               LOG(warning) << "Error handling block broadcast: " << boost::diagnostic_information( e );
            }
            catch ( const std::exception& e )
            {
               LOG(warning) << "Error handling block broadcast: " << e.what();
            }
         }
      );
      

      LOG(info) << "Connecting AMQP request handler...";
      reqhandler.connect( amqp_url );
      LOG(info) << "Connected client to AMQP server";

      LOG(info) << "Using " << jobs << " jobs";
      LOG(info) << "Starting block producer...";

      asio::signal_set signals( main_context, SIGINT, SIGTERM );

      signals.async_wait( [&]( const boost::system::error_code& err, int num )
      {
         LOG(info) << "Caught signal, shutting down...";
         asio::post(
            main_context,
            [&]()
            {
               work_context.stop();
               main_context.stop();
               client->disconnect();
            }
         );
      } );

      std::vector< std::thread > threads;
      for ( std::size_t i = 0; i < jobs + 1; i++ )
         threads.emplace_back( [&]() { work_context.run(); } );

      main_context.run();

      for ( auto& t : threads )
         t.join();

      return EXIT_SUCCESS;
   }
   catch ( const invalid_argument& e )
   {
      LOG(error) << "Invalid argument: " << e.what();
   }
   catch ( const std::exception& e )
   {
      LOG(fatal) << "An unexpected error has occurred: " << e.what();
   }
   catch ( const boost::exception& e )
   {
      LOG(fatal) << "An unexpected error has occurred: " << boost::diagnostic_information( e );
   }
   catch ( ... )
   {
      LOG(fatal) << "An unexpected error has occurred";
   }

   return EXIT_FAILURE;
}
