cmake_minimum_required(VERSION 3.10)
project(libpit)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

set(LIBPIT_SOURCE_FILES
    source/libpit.cpp)

add_library(pit STATIC ${LIBPIT_SOURCE_FILES})
