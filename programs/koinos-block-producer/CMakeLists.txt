file(GLOB HEADERS "include/*.hpp")

add_executable(koinos-block-producer
               main.cpp
               block_producer.cpp
               ${HEADERS})
target_link_libraries(koinos-block-producer Koinos::exception Koinos::crypto Koinos::types Koinos::log Koinos::mq Boost::program_options)
target_include_directories(koinos-block-producer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
install(TARGETS
   koinos-block-producer
   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)
