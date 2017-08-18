cmake_minimum_required(VERSION 2.8)

project(unplug)

include_directories("/usr/include/libnl3")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
add_executable(${PROJECT_NAME} "main.cpp")
target_link_libraries(${PROJECT_NAME} nl-3 nl-route-3)
