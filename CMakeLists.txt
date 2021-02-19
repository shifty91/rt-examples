cmake_minimum_required(VERSION 3.2)
project(rt-examples)

include(CheckIncludeFiles)

find_package(PkgConfig REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -march=native")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include_directories("common")
add_executable(cyclic cyclic/cyclic.c common/utils.c)
add_executable(etf etf/etf.c common/utils.c)
add_executable(sub etf/sub.c common/utils.c)
add_executable(deadline deadline/deadline.c common/utils.c)
add_executable(signal signal/signal.c common/utils.c)
target_link_libraries(cyclic Threads::Threads)
target_link_libraries(etf Threads::Threads)
target_link_libraries(sub Threads::Threads)
target_link_libraries(deadline Threads::Threads)
target_link_libraries(signal Threads::Threads)

configure_file(
  "${PROJECT_SOURCE_DIR}/rt_config.in"
  "${PROJECT_BINARY_DIR}/rt_config.h"
  )
include_directories("${PROJECT_BINARY_DIR}")

option(WITH_XDP "Build Examples with XDP Support" OFF)
if (WITH_XDP)
  # build etf subscriber against libbpf
  pkg_search_module(LIBBPF libbpf REQUIRED)
  link_directories(${LIBBPF_LIBRARY_DIRS})
  target_include_directories(sub PRIVATE ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(sub ${LIBBPF_LIBRARIES})

  set(CLANG_FLAGS -S -target bpf -D __BPF_TRACING__ -Wall -O2 -emit-llvm -g)
  set(LLC_FLAGS -march=bpf -filetype=obj)

  # build bpf program
  add_custom_target(xdp_sub_udp_prog_stage1 ALL
    COMMAND clang ${CLANG_FLAGS} -c -o xdp_kern_udp.ll xdp_kern_udp.c
    DEPENDS sub
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/etf
    SOURCES etf/xdp_kern_udp.c
    )
  add_custom_target(xdp_sub_raw_prog_stage1 ALL
    COMMAND clang ${CLANG_FLAGS} -c -o xdp_kern_raw.ll xdp_kern_raw.c
    DEPENDS sub
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/etf
    SOURCES etf/xdp_kern_raw.c
    )
  add_custom_target(xdp_sub_udp_prog_stage2 ALL
    COMMAND llc ${LLC_FLAGS} -o ${CMAKE_BINARY_DIR}/xdp_kern_udp.o xdp_kern_udp.ll
    DEPENDS xdp_sub_udp_prog_stage1
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/etf
    SOURCES etf/xdp_kern_udp.c
    )
  add_custom_target(xdp_sub_raw_prog_stage2 ALL
    COMMAND llc ${LLC_FLAGS} -o ${CMAKE_BINARY_DIR}/xdp_kern_raw.o xdp_kern_raw.ll
    DEPENDS xdp_sub_raw_prog_stage1
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/etf
    SOURCES etf/xdp_kern_raw.c
    )
endif()

option(WITH_LTTNG "Build with LTTNG Examples" OFF)
if (WITH_LTTNG)
  pkg_search_module(LTTNG_UST lttng-ust REQUIRED)
  add_executable(cyclic_lttng lttng/cyclic.c lttng/cyclic-tp.c common/utils.c)
  link_directories(${LTTNG_UST_LIBRARY_DIRS})
  target_include_directories(cyclic_lttng PRIVATE ${LTTNG_UST_INCLUDE_DIRS})
  target_include_directories(cyclic_lttng PRIVATE lttng)
  target_link_libraries(cyclic_lttng ${LTTNG_UST_LIBRARIES})
  target_link_libraries(cyclic_lttng Threads::Threads)
endif()

option(WITH_USDT "Build with USDT Examples" OFF)
if (WITH_USDT)
  check_include_files("sys/sdt.h" HAVE_SDT_H)
  if (NOT HAVE_SDT_H)
    message(FATAL_ERROR "sys/sdt.h not found. Consider installing systemtap!")
  endif()
  add_executable(cyclic_usdt usdt/cyclic.c common/utils.c)
  target_include_directories(cyclic_usdt PRIVATE)
  target_link_libraries(cyclic_usdt Threads::Threads)
endif()
