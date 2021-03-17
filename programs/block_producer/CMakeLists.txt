add_executable(block_producer main.cpp)
target_link_libraries(block_producer Koinos::exception Koinos::crypto Koinos::types Koinos::log Boost::program_options)
install(TARGETS
   block_producer
   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)
