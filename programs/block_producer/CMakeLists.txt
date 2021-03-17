file(GLOB HEADERS "include/*.hpp")

add_executable(block_producer
               main.cpp
               block_producer.cpp
               ${HEADERS})
target_link_libraries(block_producer Koinos::exception Koinos::crypto Koinos::types Koinos::log Koinos::mq Boost::program_options)
target_include_directories(block_producer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
install(TARGETS
   block_producer
   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)
