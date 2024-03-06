add_library(block_production
  koinos/block_production/block_producer.cpp
  koinos/block_production/federated_producer.cpp
  koinos/block_production/pob_producer.cpp
  koinos/block_production/pow_producer.cpp

  koinos/block_production/block_producer.hpp
  koinos/block_production/federated_producer.hpp
  koinos/block_production/pob_producer.hpp
  koinos/block_production/pow_producer.hpp)

target_link_libraries(
  block_production
    PUBLIC
      Koinos::exception
      Koinos::crypto
      Koinos::proto
      Koinos::log
      Koinos::mq)

target_include_directories(
  block_production
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

koinos_add_format(TARGET block_production)

add_executable(koinos_block_producer koinos_block_producer.cpp)

target_link_libraries(
  koinos_block_producer
    PUBLIC
      block_production
      Koinos::exception
      Koinos::crypto
      Koinos::proto
      Koinos::log
      Koinos::mq
      Koinos::git
      Boost::program_options
      protobuf::libprotobuf
      yaml-cpp)

koinos_add_format(TARGET koinos_block_producer)

koinos_install(TARGETS koinos_block_producer)
