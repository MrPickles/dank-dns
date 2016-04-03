cmake_minimum_required(VERSION 2.6)

project(parse)
include_directories(sparsehash-2.0.2/src)
add_executable(
    parse
    Main.cpp
    ParseDNS.cpp
    SipHash.cpp
)
target_link_libraries(parse pcap rt)
set(CMAKE_CXX_FLAGS "-O3 -Wall")
set(CMAKE_C_FLAGS "-O3 -Wall")

