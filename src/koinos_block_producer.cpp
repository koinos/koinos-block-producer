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
#include <koinos/broadcast/broadcast.pb.h>
#include <koinos/exception.hpp>
#include <koinos/log.hpp>
#include <koinos/mq/request_handler.hpp>
#include <koinos/rpc/chain/chain_rpc.pb.h>
#include <koinos/rpc/mempool/mempool_rpc.pb.h>
#include <koinos/util/base58.hpp>
#include <koinos/util/base64.hpp>
#include <koinos/util/conversion.hpp>
#include <koinos/util/hex.hpp>
#include <koinos/util/options.hpp>
#include <koinos/util/random.hpp>
#include <koinos/util/services.hpp>

#include "git_version.h"

#define FEDERATED_ALGORITHM "federated"
#define POW_ALGORITHM       "pow"
#define POB_ALGORITHM       "pob"

#define HELP_OPTION                    "help"
#define VERSION_OPTION                 "version"
#define BASEDIR_OPTION                 "basedir"
#define AMQP_OPTION                    "amqp"
#define AMQP_DEFAULT                   "amqp://guest:guest@localhost:5672/"
#define LOG_LEVEL_OPTION               "log-level"
#define LOG_LEVEL_DEFAULT              "info"
#define LOG_DIR_OPTION                 "log-dir"
#define LOG_DIR_DEFAULT                ""
#define LOG_COLOR_OPTION               "log-color"
#define LOG_COLOR_DEFAULT              true
#define LOG_DATETIME_OPTION            "log-datetime"
#define LOG_DATETIME_DEFAULT           true
#define INSTANCE_ID_OPTION             "instance-id"
#define ALGORITHM_OPTION               "algorithm"
#define JOBS_OPTION                    "jobs"
#define JOBS_DEFAULT                   uint64_t( 2 )
#define WORK_GROUPS_OPTION             "work-groups"
#define PRIVATE_KEY_FILE_OPTION        "private-key-file"
#define PRIVATE_KEY_FILE_DEFAULT       "private.key"
#define POW_CONTRACT_ID_OPTION         "pow-contract-id"
#define GOSSIP_PRODUCTION_OPTION       "gossip-production"
#define GOSSIP_PRODUCTION_DEFAULT      bool( true )
#define RESOURCES_LOWER_BOUND_OPTION   "resources-lower-bound"
#define RESOURCES_LOWER_BOUND_DEFAULT  uint64_t( 75 )
#define RESOURCES_UPPER_BOUND_OPTION   "resources-upper-bound"
#define RESOURCES_UPPER_BOUND_DEFAULT  uint64_t( 90 )
#define MAX_INCLUSION_ATTEMPTS_OPTION  "max-inclusion-attempts"
#define MAX_INCLUSION_ATTEMPTS_DEFAULT uint64_t( 2'000 )
#define APPROVE_PROPOSALS_OPTION       "approve-proposals"
#define PRODUCER_ADDRESS_OPTION        "producer"

KOINOS_DECLARE_EXCEPTION( service_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( invalid_argument, service_exception );
KOINOS_DECLARE_DERIVED_EXCEPTION( unable_to_write, service_exception );

using namespace boost;
using namespace koinos;

const std::string& version_string();

int main( int argc, char** argv )
{
  std::atomic< bool > stopped = false;
  int retcode                 = EXIT_SUCCESS;
  std::vector< std::thread > threads;

  asio::io_context work_context, client_context, request_context, main_context;
  std::unique_ptr< block_production::block_producer > producer;
  auto client = std::make_shared< mq::client >( client_context );
  mq::request_handler reqhandler( request_context );

  try
  {
    program_options::options_description options;

    // clang-format off
    options.add_options()
      ( HELP_OPTION ",h"                  , "Print this help message and exit." )
      ( VERSION_OPTION ",v"               , "Print version string and exit" )
      ( BASEDIR_OPTION ",d"               , program_options::value< std::string >()->default_value( util::get_default_base_directory().string() ), "Koinos base directory" )
      ( APPROVE_PROPOSALS_OPTION ",k"     , program_options::value< std::vector< std::string > >()->multitoken(), "A list a proposal to approve when producing a block" )
      ( AMQP_OPTION ",a"                  , program_options::value< std::string >(), "AMQP server URL" )
      ( LOG_LEVEL_OPTION ",l"             , program_options::value< std::string >(), "The log filtering level" )
      ( INSTANCE_ID_OPTION ",i"           , program_options::value< std::string >(), "An ID that uniquely identifies the instance" )
      ( ALGORITHM_OPTION ",g"             , program_options::value< std::string >(), "The consensus algorithm to use" )
      ( JOBS_OPTION ",j"                  , program_options::value< uint64_t >()   , "The number of worker jobs" )
      ( WORK_GROUPS_OPTION ",w"           , program_options::value< uint64_t >()   , "The number of worker groups" )
      ( PRIVATE_KEY_FILE_OPTION ",p"      , program_options::value< std::string >(), "The private key file" )
      ( POW_CONTRACT_ID_OPTION ",c"       , program_options::value< std::string >(), "The PoW contract ID" )
      ( MAX_INCLUSION_ATTEMPTS_OPTION ",m", program_options::value< uint64_t >()   , "The maximum transaction inclusion attempts per block" )
      ( RESOURCES_LOWER_BOUND_OPTION ",z" , program_options::value< uint64_t >()   , "The resource utilization lower bound as a percentage" )
      ( RESOURCES_UPPER_BOUND_OPTION ",x" , program_options::value< uint64_t >()   , "The resource utilization upper bound as a percentage" )
      ( GOSSIP_PRODUCTION_OPTION          , program_options::value< bool >()       , "Use p2p gossip status to determine block production" )
      ( PRODUCER_ADDRESS_OPTION ",f"      , program_options::value< std::string >(), "The beneficiary address used during PoB production" )
      ( LOG_DIR_OPTION                    , program_options::value< std::string >(), "The logging directory" )
      ( LOG_COLOR_OPTION                  , program_options::value< bool >()       , "Log color toggle" )
      ( LOG_DATETIME_OPTION               , program_options::value< bool >()       , "Log datetime on console toggle" );
    // clang-format on

    program_options::variables_map args;
    program_options::store( program_options::parse_command_line( argc, argv, options ), args );

    if( args.count( HELP_OPTION ) )
    {
      std::cout << options << std::endl;
      return EXIT_SUCCESS;
    }

    if( args.count( VERSION_OPTION ) )
    {
      const auto& v_str = version_string();
      std::cout.write( v_str.c_str(), v_str.size() );
      std::cout << std::endl;
      return EXIT_SUCCESS;
    }

    auto basedir = std::filesystem::path{ args[ BASEDIR_OPTION ].as< std::string >() };
    if( basedir.is_relative() )
      basedir = std::filesystem::current_path() / basedir;

    YAML::Node config;
    YAML::Node global_config;
    YAML::Node block_producer_config;

    auto yaml_config = basedir / "config.yml";
    if( !std::filesystem::exists( yaml_config ) )
    {
      yaml_config = basedir / "config.yaml";
    }

    if( std::filesystem::exists( yaml_config ) )
    {
      config                = YAML::LoadFile( yaml_config );
      global_config         = config[ "global" ];
      block_producer_config = config[ util::service::block_producer ];
    }

    // clang-format off
    auto amqp_url          = util::get_option< std::string >( AMQP_OPTION, AMQP_DEFAULT, args, block_producer_config, global_config );
    auto log_level         = util::get_option< std::string >( LOG_LEVEL_OPTION, LOG_LEVEL_DEFAULT, args, block_producer_config, global_config );
    auto log_dir           = util::get_option< std::string >( LOG_DIR_OPTION, LOG_DIR_DEFAULT, args, block_producer_config, global_config );
    auto log_color         = util::get_option< bool >( LOG_COLOR_OPTION, LOG_COLOR_DEFAULT, args, block_producer_config, global_config );
    auto log_datetime      = util::get_option< bool >( LOG_DATETIME_OPTION, LOG_DATETIME_DEFAULT, args, block_producer_config, global_config );
    auto instance_id       = util::get_option< std::string >( INSTANCE_ID_OPTION, util::random_alphanumeric( 5 ), args, block_producer_config, global_config );
    auto algorithm         = util::get_option< std::string >( ALGORITHM_OPTION, FEDERATED_ALGORITHM, args, block_producer_config, global_config );
    auto jobs              = util::get_option< uint64_t >( JOBS_OPTION, std::max( JOBS_DEFAULT, uint64_t( std::thread::hardware_concurrency() ) ), args, block_producer_config, global_config );
    auto work_groups       = util::get_option< uint64_t >( WORK_GROUPS_OPTION, jobs, args, block_producer_config, global_config );
    auto pk_file           = util::get_option< std::string >( PRIVATE_KEY_FILE_OPTION, PRIVATE_KEY_FILE_DEFAULT, args, block_producer_config, global_config );
    auto pow_id            = util::get_option< std::string >( POW_CONTRACT_ID_OPTION, "", args, block_producer_config, global_config );
    auto rcs_lbound        = util::get_option< uint64_t >( RESOURCES_LOWER_BOUND_OPTION, RESOURCES_LOWER_BOUND_DEFAULT, args, block_producer_config, global_config );
    auto producer_addr     = util::get_option< std::string >( PRODUCER_ADDRESS_OPTION, "", args, block_producer_config, global_config );
    auto rcs_ubound        = util::get_option< uint64_t >( RESOURCES_UPPER_BOUND_OPTION, RESOURCES_UPPER_BOUND_DEFAULT, args, block_producer_config, global_config );
    auto max_attempts      = util::get_option< uint64_t >( MAX_INCLUSION_ATTEMPTS_OPTION, MAX_INCLUSION_ATTEMPTS_DEFAULT, args, block_producer_config, global_config );
    auto gossip_production = util::get_option< bool >( GOSSIP_PRODUCTION_OPTION, GOSSIP_PRODUCTION_DEFAULT, args, block_producer_config, global_config );
    auto proposal_ids      = util::get_options< std::string >( APPROVE_PROPOSALS_OPTION, args, block_producer_config, global_config );
    // clang-format on

    std::optional< std::filesystem::path > logdir_path;
    if( !log_dir.empty() )
    {
      logdir_path = std::make_optional< std::filesystem::path >( log_dir );
      if( logdir_path->is_relative() )
        logdir_path = basedir / util::service::block_producer / *logdir_path;
    }

    koinos::initialize_logging( util::service::block_producer,
                                instance_id,
                                log_level,
                                logdir_path,
                                log_color,
                                log_datetime );

    LOG( info ) << version_string();

    KOINOS_ASSERT( rcs_lbound >= 0 && rcs_lbound <= 100,
                   invalid_argument,
                   "resource lower bound out of range [0..100]" );
    KOINOS_ASSERT( rcs_ubound >= 0 && rcs_ubound <= 100,
                   invalid_argument,
                   "resource upper bound out of range [0..100]" );

    KOINOS_ASSERT( jobs > 1, invalid_argument, "jobs must be greater than 1" );

    if( config.IsNull() )
    {
      LOG( warning ) << "Could not find config (config.yml or config.yaml expected), using default values";
    }

    std::filesystem::path private_key_file{ pk_file };
    if( private_key_file.is_relative() )
      private_key_file = basedir / util::service::block_producer / private_key_file;

    if( !std::filesystem::exists( private_key_file ) )
    {
      LOG( info ) << "Could not find private key file at '" << private_key_file << "', generating a new key...";

      if( !std::filesystem::exists( private_key_file.parent_path() ) )
        std::filesystem::create_directories( private_key_file.parent_path() );

      std::ofstream ofs( private_key_file );

      auto seed        = koinos::util::random_alphanumeric( 64 );
      auto secret      = koinos::crypto::hash( koinos::crypto::multicodec::sha2_256, seed );
      auto private_key = koinos::crypto::private_key::regenerate( secret );

      ofs << private_key.to_wif() << std::endl;
    }

    crypto::private_key signing_key;

    try
    {
      std::ifstream ifs( private_key_file );
      std::string private_key_wif;
      std::getline( ifs, private_key_wif );
      signing_key = crypto::private_key::from_wif( private_key_wif );
    }
    catch( const std::exception& e )
    {
      KOINOS_THROW( invalid_argument,
                    "unable to parse private key file at ${f}, ${r}",
                    ( "f", private_key_file )( "r", e.what() ) );
    }

    std::filesystem::path public_key_file = basedir / util::service::block_producer / "public.key";

    std::ofstream pubfile;
    pubfile.open( public_key_file );
    KOINOS_ASSERT( pubfile.is_open(),
                   unable_to_write,
                   "unable to write public key file to disk at ${f}",
                   ( "f", public_key_file ) );
    pubfile << util::to_base64( signing_key.get_public_key().serialize() ) << std::endl;
    pubfile.close();

    LOG( info ) << "Public address: " << util::to_base58( signing_key.get_public_key().to_address_bytes() );
    LOG( info ) << "Public key: " << util::to_base64( signing_key.get_public_key().serialize() );
    if( !producer_addr.empty() )
      LOG( info ) << "Producer address: " << producer_addr;
    LOG( info ) << "Block resource utilization lower bound: " << rcs_lbound << "%, upper bound: " << rcs_ubound << "%";
    LOG( info ) << "Maximum transaction inclusion attempts per block: " << max_attempts;

    std::vector< std::string > approved_proposals;

    for( const auto& id: proposal_ids )
    {
      try
      {
        approved_proposals.emplace_back( util::from_hex< std::string >( id ) );
      }
      catch( const std::exception& e )
      {
        KOINOS_THROW( invalid_argument, "could not parse proposal id '${p}'", ( "p", id ) );
      }
    }

    if( proposal_ids.size() )
    {
      LOG( info ) << "Approved Proposals:";
      for( const auto& p: proposal_ids )
      {
        LOG( info ) << " - " << p;
      }
    }

    asio::signal_set signals( work_context );
    signals.add( SIGINT );
    signals.add( SIGTERM );
#if defined( SIGQUIT )
    signals.add( SIGQUIT );
#endif

    signals.async_wait(
      [ & ]( const boost::system::error_code& err, int num )
      {
        LOG( info ) << "Caught signal, shutting down...";
        stopped = true;
        main_context.stop();
      } );

    threads.emplace_back(
      [ & ]()
      {
        client_context.run();
      } );
    threads.emplace_back(
      [ & ]()
      {
        client_context.run();
      } );
    threads.emplace_back(
      [ & ]()
      {
        request_context.run();
      } );
    threads.emplace_back(
      [ & ]()
      {
        request_context.run();
      } );

    LOG( info ) << "Connecting AMQP client...";
    client->connect( amqp_url );
    LOG( info ) << "Established AMQP client connection to the server";

    LOG( info ) << "Attempting to connect to chain...";
    rpc::chain::chain_request creq;
    creq.mutable_reserved();
    client->rpc( util::service::chain, creq.SerializeAsString() ).get();
    LOG( info ) << "Established connection to chain";

    LOG( info ) << "Attempting to connect to mempool...";
    rpc::mempool::mempool_request mreq;
    mreq.mutable_reserved();
    client->rpc( util::service::mempool, mreq.SerializeAsString() ).get();
    LOG( info ) << "Established connection to mempool";

    if( algorithm == FEDERATED_ALGORITHM )
    {
      LOG( info ) << "Using " << FEDERATED_ALGORITHM << " algorithm";
      producer = std::make_unique< block_production::federated_producer >( signing_key,
                                                                           main_context,
                                                                           work_context,
                                                                           client,
                                                                           rcs_lbound,
                                                                           rcs_ubound,
                                                                           max_attempts,
                                                                           gossip_production,
                                                                           approved_proposals );
    }
    else if( algorithm == POB_ALGORITHM )
    {
      LOG( info ) << "Using " << POB_ALGORITHM << " algorithm";

      KOINOS_ASSERT( !producer_addr.empty(), invalid_argument, "A producer address must be provided" );

      auto producer_address = util::from_base58< std::string >( producer_addr );

      producer = std::make_unique< block_production::pob_producer >( signing_key,
                                                                     main_context,
                                                                     work_context,
                                                                     client,
                                                                     rcs_lbound,
                                                                     rcs_ubound,
                                                                     max_attempts,
                                                                     gossip_production,
                                                                     approved_proposals,
                                                                     producer_address );

      LOG( info ) << "Using " << work_groups << " work groups";
    }
    else if( algorithm == POW_ALGORITHM )
    {
      LOG( info ) << "Using " << POW_ALGORITHM << " algorithm";

      KOINOS_ASSERT( !pow_id.empty(), invalid_argument, "A proof of work contract ID must be provided" );

      auto pow_address = util::from_base58< std::string >( pow_id );

      producer = std::make_unique< block_production::pow_producer >( signing_key,
                                                                     main_context,
                                                                     work_context,
                                                                     client,
                                                                     rcs_lbound,
                                                                     rcs_ubound,
                                                                     max_attempts,
                                                                     gossip_production,
                                                                     approved_proposals,
                                                                     pow_address,
                                                                     work_groups );

      LOG( info ) << "Using " << work_groups << " work groups";
    }
    else
    {
      KOINOS_THROW( invalid_argument, "unrecognized consensus algorithm" );
    }

    for( std::size_t i = 0; i < jobs + 1; i++ )
      threads.emplace_back(
        [ & ]()
        {
          work_context.run();
        } );

    reqhandler.add_broadcast_handler( "koinos.mempool.block_accepted",
                                      [ & ]( const std::string& msg )
                                      {
                                        try
                                        {
                                          broadcast::block_accepted bam;
                                          bam.ParseFromString( msg );
                                          producer->on_block_accept( bam );
                                        }
                                        catch( const boost::exception& e )
                                        {
                                          LOG( warning )
                                            << "Error handling block broadcast: " << boost::diagnostic_information( e );
                                        }
                                        catch( const std::exception& e )
                                        {
                                          LOG( warning ) << "Error handling block broadcast: " << e.what();
                                        }
                                      } );

    reqhandler.add_broadcast_handler( "koinos.gossip.status",
                                      [ & ]( const std::string& msg )
                                      {
                                        try
                                        {
                                          broadcast::gossip_status gsm;
                                          gsm.ParseFromString( msg );
                                          producer->on_gossip_status( gsm );
                                        }
                                        catch( const boost::exception& e )
                                        {
                                          LOG( warning )
                                            << "Error handling block broadcast: " << boost::diagnostic_information( e );
                                        }
                                        catch( const std::exception& e )
                                        {
                                          LOG( warning ) << "Error handling block broadcast: " << e.what();
                                        }
                                      } );

    LOG( info ) << "Connecting AMQP request handler...";
    reqhandler.connect( amqp_url );
    LOG( info ) << "Established request handler connection to the AMQP server";

    LOG( info ) << "Using " << jobs << " jobs";
    LOG( info ) << "Starting block producer...";

    auto work = asio::make_work_guard( main_context );
    main_context.run();
  }
  catch( const invalid_argument& e )
  {
    LOG( error ) << "Invalid argument: " << e.what();
    retcode = EXIT_FAILURE;
  }
  catch( const koinos::exception& e )
  {
    if( !stopped )
    {
      LOG( fatal ) << "An unexpected error has occurred: " << e.what();
      retcode = EXIT_FAILURE;
    }
  }
  catch( const std::exception& e )
  {
    LOG( fatal ) << "An unexpected error has occurred: " << e.what();
    retcode = EXIT_FAILURE;
  }
  catch( const boost::exception& e )
  {
    LOG( fatal ) << "An unexpected error has occurred: " << boost::diagnostic_information( e );
    retcode = EXIT_FAILURE;
  }
  catch( ... )
  {
    LOG( fatal ) << "An unexpected error has occurred";
    retcode = EXIT_FAILURE;
  }

  for( auto& t: threads )
    t.join();

  LOG( info ) << "Shutdown gracefully";

  return EXIT_FAILURE;
}

const std::string& version_string()
{
  static std::string v_str = "Koinos Block Producer v";
  v_str += std::to_string( KOINOS_MAJOR_VERSION ) + "." + std::to_string( KOINOS_MINOR_VERSION ) + "."
           + std::to_string( KOINOS_PATCH_VERSION );
  v_str += " (" + std::string( KOINOS_GIT_HASH ) + ")";
  return v_str;
}
