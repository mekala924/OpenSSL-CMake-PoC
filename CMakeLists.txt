cmake_minimum_required(VERSION 3.6)
project(OpenSSL-CMake-PoC CXX C)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(openssl)
add_subdirectory(test-tool)
