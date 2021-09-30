add_executable(koinos_block_producer
               main.cpp
               ${HEADERS})
target_link_libraries(koinos_block_producer Koinos::exception Koinos::crypto Koinos::proto Koinos::log Koinos::mq Koinos::block_production Boost::program_options protobuf::libprotobuf yaml-cpp)
install(TARGETS
   koinos_block_producer
   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)
