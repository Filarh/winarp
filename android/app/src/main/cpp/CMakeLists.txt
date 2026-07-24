cmake_minimum_required(VERSION 3.22.1)
project(winarp_native)

add_library(winarp_native SHARED arp_native.cpp)

find_library(log-lib log)

target_link_libraries(winarp_native ${log-lib})
