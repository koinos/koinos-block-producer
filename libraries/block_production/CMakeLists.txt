file(GLOB HEADERS "include/koinos/block_production/*.hpp")

add_library(koinos_block_production
            block_producer.cpp
            federated_producer.cpp
            pow_producer.cpp
            ${HEADERS})
target_link_libraries(koinos_block_production Koinos::exception Koinos::crypto Koinos::types Koinos::log Koinos::mq)
target_include_directories(koinos_block_production PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(Koinos::block_production ALIAS koinos_block_production)
install(TARGETS
   koinos_block_production
   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)
