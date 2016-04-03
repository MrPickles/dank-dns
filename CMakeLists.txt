cmake_minimum_required(VERSION 2.6)

project(parse)

# Location of header files
include_directories(include)

# Add all source files
file(GLOB SOURCES "src/*.cpp")

add_executable(
    parse
    ${SOURCES}
)

target_link_libraries(parse pcap)
set(CMAKE_CXX_FLAGS "-O3 -Wall")
set(CMAKE_C_FLAGS "-O3 -Wall")

