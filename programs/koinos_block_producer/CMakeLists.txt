file(GLOB HEADERS "include/*.hpp")

add_executable(koinos_block_producer
               main.cpp
               block_producer.cpp
               ${HEADERS})
target_link_libraries(koinos_block_producer Koinos::exception Koinos::crypto Koinos::types Koinos::log Koinos::mq Boost::program_options yaml-cpp)
target_include_directories(koinos_block_producer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
install(TARGETS
   koinos_block_producer
   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)
