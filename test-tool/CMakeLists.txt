file(GLOB_RECURSE SOURCES *.cpp)

add_executable(test-tool ${SOURCES})

set_target_properties(test-tool PROPERTIES INCLUDE_DIRECTORIES ${OPENSSL_INCLUDES})

target_link_libraries(test-tool ${OPENSSL_LIBRARIES})

add_dependencies(test-tool openssl)
