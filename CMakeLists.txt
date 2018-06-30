cmake_minimum_required(VERSION 3.2)
project(rt-examples)

set(CMAKE_CC_FLAGS "${CMAKE_CC_FLAGS} -pedantic -Wall -march=native")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include_directories("common" "cyclic")
add_executable(cyclic cyclic/cyclic.c common/utils.c)
add_executable(deadline deadline/deadline.c common/utils.c)
add_executable(signal signal/signal.c common/utils.c)
target_link_libraries(cyclic Threads::Threads)
target_link_libraries(deadline Threads::Threads)
target_link_libraries(signal Threads::Threads)
