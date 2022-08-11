#include <atomic>
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
#include <koinos/block_production/pob_producer.hpp>
#include <koinos/block_production/pow_producer.hpp>
#include <koinos/exception.hpp>
#include <koinos/log.hpp>
#include <koinos/mq/request_handler.hpp>
#include <koinos/broadcast/broadcast.pb.h>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/rpc/mempool/mempool_rpc.pb.h>
#include <koinos/util/base58.hpp>
#include <koinos/util/conversion.hpp>
#include <koinos/util/hex.hpp>
#include <koinos/util/options.hpp>
#include <koinos/util/random.hpp>
#include <koinos/util/services.hpp>

#define FEDERATED_ALGORITHM                "federated"
#define POW_ALGORITHM                      "pow"
#define POB_ALGORITHM                      "pob"

#define HELP_OPTION                        "help"
#define BASEDIR_OPTION                     "basedir"
#define AMQP_OPTION                        "amqp"
#define AMQP_DEFAULT                       "amqp://guest:guest@localhost:5672/"
#define LOG_LEVEL_OPTION                   "log-level"
#define LOG_LEVEL_DEFAULT                  "info"
#define INSTANCE_ID_OPTION                 "instance-id"
#define ALGORITHM_OPTION                   "algorithm"
#define JOBS_OPTION                        "jobs"
#define JOBS_DEFAULT                       uint64_t( 2 )
#define WORK_GROUPS_OPTION                 "work-groups"
#define PRIVATE_KEY_FILE_OPTION            "private-key-file"
#define PRIVATE_KEY_FILE_DEFAULT           "private.key"
#define POW_CONTRACT_ID_OPTION             "pow-contract-id"
#define POB_CONTRACT_ID_OPTION             "pob-contract-id"
#define VHP_CONTRACT_ID_OPTION             "vhp-contract-id"
#define GOSSIP_PRODUCTION_OPTION           "gossip-production"
#define GOSSIP_PRODUCTION_DEFAULT          bool( true )
#define RESOURCES_LOWER_BOUND_OPTION       "resources-lower-bound"
#define RESOURCES_LOWER_BOUND_DEFAULT      uint64_t( 75 )
#define RESOURCES_UPPER_BOUND_OPTION       "resources-upper-bound"
#define RESOURCES_UPPER_BOUND_DEFAULT      uint64_t( 90 )
#define MAX_INCLUSION_ATTEMPTS_OPTION      "max-inclusion-attempts"
#define MAX_INCLUSION_ATTEMPTS_DEFAULT     uint64_t( 2000 )
#define APPROVE_PROPOSALS_OPTION           "approve-proposals"
#define PRODUCER_ADDRESS_OPTION            "producer"

KOINOS_DECLARE_EXCEPTION( service_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( invalid_argument, service_exception );

using namespace boost;
using namespace koinos;

int main( int argc, char** argv )
{
   std::atomic< bool > stopped = false;
   int retcode = EXIT_SUCCESS;
   std::vector< std::thread > threads;

   asio::io_context work_context, client_context, request_context, main_context;
   std::unique_ptr< block_production::block_producer > producer;
   auto client = std::make_shared< mq::client >( client_context );
   mq::request_handler reqhandler( request_context );

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
         (POB_CONTRACT_ID_OPTION           ",b", program_options::value< std::string >(), "The PoB contract ID")
         (VHP_CONTRACT_ID_OPTION           ",e", program_options::value< std::string >(), "The VHP contract ID")
         (MAX_INCLUSION_ATTEMPTS_OPTION    ",m", program_options::value< uint64_t    >(), "The maximum transaction inclusion attempts per block")
         (RESOURCES_LOWER_BOUND_OPTION     ",z", program_options::value< uint64_t    >(), "The resource utilization lower bound as a percentage")
         (RESOURCES_UPPER_BOUND_OPTION     ",x", program_options::value< uint64_t    >(), "The resource utilization upper bound as a percentage")
         (GOSSIP_PRODUCTION_OPTION             , program_options::value< bool        >(), "Use p2p gossip status to determine block production")
         (PRODUCER_ADDRESS_OPTION          ",f", program_options::value< std::string >(), "The beneficiary address used during PoB production")
         (APPROVE_PROPOSALS_OPTION         ",v", program_options::value< std::vector< std::string > >()->multitoken(), "A list a proposal to approve when producing a block");

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
      auto jobs         = util::get_option< uint64_t >( JOBS_OPTION, std::max( JOBS_DEFAULT, uint64_t( std::thread::hardware_concurrency() ) ), args, block_producer_config, global_config );
      auto work_groups  = util::get_option< uint64_t    >( WORK_GROUPS_OPTION, jobs, args, block_producer_config, global_config );
      auto pk_file      = util::get_option< std::string >( PRIVATE_KEY_FILE_OPTION, PRIVATE_KEY_FILE_DEFAULT, args, block_producer_config, global_config );
      auto pow_id       = util::get_option< std::string >( POW_CONTRACT_ID_OPTION, "", args, block_producer_config, global_config );
      auto pob_id       = util::get_option< std::string >( POB_CONTRACT_ID_OPTION, "", args, block_producer_config, global_config );
      auto vhp_id       = util::get_option< std::string >( VHP_CONTRACT_ID_OPTION, "", args, block_producer_config, global_config );
      auto rcs_lbound   = util::get_option< uint64_t    >( RESOURCES_LOWER_BOUND_OPTION, RESOURCES_LOWER_BOUND_DEFAULT, args, block_producer_config, global_config );
      auto producer_addr     = util::get_option< std::string >( PRODUCER_ADDRESS_OPTION, "", args, block_producer_config, global_config );
      auto rcs_ubound        = util::get_option< uint64_t    >( RESOURCES_UPPER_BOUND_OPTION, RESOURCES_UPPER_BOUND_DEFAULT, args, block_producer_config, global_config );
      auto max_attempts      = util::get_option< uint64_t    >( MAX_INCLUSION_ATTEMPTS_OPTION, MAX_INCLUSION_ATTEMPTS_DEFAULT, args, block_producer_config, global_config );
      auto gossip_production = util::get_option< bool        >( GOSSIP_PRODUCTION_OPTION, GOSSIP_PRODUCTION_DEFAULT, args, block_producer_config, global_config );
      auto proposal_ids      = util::get_options< std::string >( APPROVE_PROPOSALS_OPTION, args, block_producer_config, global_config );

      initialize_logging( util::service::block_producer, instance_id, log_level, basedir / util::service::block_producer / "logs" );

      KOINOS_ASSERT( rcs_lbound >= 0 && rcs_lbound <= 100, invalid_argument, "resource lower bound out of range [0..100]" );
      KOINOS_ASSERT( rcs_ubound >= 0 && rcs_ubound <= 100, invalid_argument, "resource upper bound out of range [0..100]" );

      KOINOS_ASSERT( jobs > 1, invalid_argument, "jobs must be greater than 1" );

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

      std::vector< std::string > approved_proposals;

      for ( const auto& id : proposal_ids )
      {
         try
         {
            approved_proposals.emplace_back( util::from_hex< std::string >( id ) );
         }
         catch( const std::exception& e )
         {
            KOINOS_THROW( invalid_argument, "could not parse proposal id '${p}'", ("p", id) );
         }
      }

      if ( proposal_ids.size() )
      {
         LOG(info) << "Approved Proposals:";
         for( const auto& p : proposal_ids )
         {
            LOG(info) << " - " << p;
         }
      }

      asio::signal_set signals( work_context );
      signals.add( SIGINT );
      signals.add( SIGTERM );
#if defined( SIGQUIT )
      signals.add( SIGQUIT );
#endif

      signals.async_wait( [&]( const boost::system::error_code& err, int num )
      {
         LOG(info) << "Caught signal, shutting down...";
         stopped = true;
         main_context.stop();
      } );

      threads.emplace_back( [&]() { client_context.run(); } );
      threads.emplace_back( [&]() { client_context.run(); } );
      threads.emplace_back( [&]() { request_context.run(); } );
      threads.emplace_back( [&]() { request_context.run(); } );

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
            gossip_production,
            approved_proposals
         );
      }
      else if ( algorithm == POB_ALGORITHM )
      {
         LOG(info) << "Using " << POB_ALGORITHM << " algorithm";

         KOINOS_ASSERT( !pob_id.empty(), invalid_argument, "A proof of burn contract ID must be provided" );
         KOINOS_ASSERT( !vhp_id.empty(), invalid_argument, "A VHP contract ID must be provided" );
         KOINOS_ASSERT( !producer_addr.empty(), invalid_argument, "A producer address must be provided");

         auto pob_address = util::from_base58< std::string >( pob_id );
         auto vhp_address = util::from_base58< std::string >( vhp_id );
         auto producer_address = util::from_base58< std::string >( producer_addr );

         producer = std::make_unique< block_production::pob_producer >(
            signing_key,
            main_context,
            work_context,
            client,
            rcs_lbound,
            rcs_ubound,
            max_attempts,
            gossip_production,
            approved_proposals,
            pob_address,
            vhp_address,
            producer_address
         );

         LOG(info) << "Using " << work_groups << " work groups";
      }
      else if ( algorithm == POW_ALGORITHM )
      {
         LOG(info) << "Using " << POW_ALGORITHM << " algorithm";

         KOINOS_ASSERT( !pow_id.empty(), invalid_argument, "A proof of work contract ID must be provided" );

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
            approved_proposals,
            pow_address,
            work_groups
         );

         LOG(info) << "Using " << work_groups << " work groups";
      }
      else
      {
         KOINOS_THROW( invalid_argument, "unrecognized consensus algorithm" );
      }

      for ( std::size_t i = 0; i < jobs + 1; i++ )
         threads.emplace_back( [&]() { work_context.run(); } );

      reqhandler.add_broadcast_handler(
         "koinos.block.accept",
         [&]( const std::string& msg )
         {
            try
            {
               broadcast::block_accepted bam;
               bam.ParseFromString( msg );
               producer->on_block_accept( bam );
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
      LOG(info) << "Established request handler connection to the AMQP server";

      LOG(info) << "Using " << jobs << " jobs";
      LOG(info) << "Starting block producer...";

      auto work = asio::make_work_guard( main_context );
      main_context.run();
   }
   catch ( const invalid_argument& e )
   {
      LOG(error) << "Invalid argument: " << e.what();
      retcode = EXIT_FAILURE;
   }
   catch ( const koinos::exception& e )
   {
      if ( !stopped )
      {
         LOG(fatal) << "An unexpected error has occurred: " << e.what();
         retcode = EXIT_FAILURE;
      }
   }
   catch ( const std::exception& e )
   {
      LOG(fatal) << "An unexpected error has occurred: " << e.what();
      retcode = EXIT_FAILURE;
   }
   catch ( const boost::exception& e )
   {
      LOG(fatal) << "An unexpected error has occurred: " << boost::diagnostic_information( e );
      retcode = EXIT_FAILURE;
   }
   catch ( ... )
   {
      LOG(fatal) << "An unexpected error has occurred";
      retcode = EXIT_FAILURE;
   }

   for ( auto& t : threads )
      t.join();

   LOG(info) << "Shutdown gracefully";

   return EXIT_FAILURE;
}
