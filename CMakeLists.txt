cmake_minimum_required(VERSION 3.20)
project("ardp" VERSION 1.0.0 LANGUAGES C CXX)

# 启动对99标准的支持
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED OFF)
set(CMAKE_C_EXTENSIONS OFF)

# 启动对C++11标准的支持
set(CMAKE_CXX_STANDARD 11)
# 显式要求指明支持C++标准
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing -g")
#set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -std=c++11 -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing -g")
#set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
set (CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules;${CMAKE_MODULE_PATH}")

#include(cmake/Modules/libnetfilter_queue.cmake)
include(cmake/Modules/pcap-1.9.0.cmake)
include(cmake/Modules/jansson-2.14.cmake)
include(cmake/Modules/userspace-rcu-0.13.1.cmake)
include(cmake/Modules/pcre2-10.40.cmake)
include(cmake/Modules/hyperscan-5.4.0.cmake)

set(CMAKE_BUILD_TYPE "Release")
# PROJECT_SOURCE_DIR指的是工程顶层目录
include_directories(
        "${PROJECT_SOURCE_DIR}"
)

find_package (Threads REQUIRED)
#find_package (URCU REQUIRED)
find_package (NFQ REQUIRED)
#if(URCU_FOUND)
#    message("liburcu found")
#else()
#    message("required liburcu not found")
#endif()

if(NFQ_FOUND)
    message("libnetfilter_queue found")
else()
    message("libnetfilter_queue not found")
endif()


add_library(base "")
target_sources(base
        PRIVATE
        "${CMAKE_SOURCE_DIR}/base/rcu_map.c"
        "${CMAKE_SOURCE_DIR}/base/timer_queue.c"
        "${CMAKE_SOURCE_DIR}/base/timer_wheel.c"
        "${CMAKE_SOURCE_DIR}/base/asm.c"
        "${CMAKE_SOURCE_DIR}/base/asn1.c"
        "${CMAKE_SOURCE_DIR}/base/bitmap.c"
        "${CMAKE_SOURCE_DIR}/base/helper.c"
        "${CMAKE_SOURCE_DIR}/base/tree.c"
        "${CMAKE_SOURCE_DIR}/base/debug.c"
        "${CMAKE_SOURCE_DIR}/base/event_handler.cc"
        )
target_link_libraries(base ${URCU_LIBRARY})

add_library(dpi "")
target_sources(dpi
        PRIVATE
        "${CMAKE_SOURCE_DIR}/dpi/dpi_parser.cc"
        "${CMAKE_SOURCE_DIR}/dpi/dpi_frag.cc"
        "${CMAKE_SOURCE_DIR}/dpi/dpi_entry.cc"
        "${CMAKE_SOURCE_DIR}/dpi/dpi_packet.cc"
        "${CMAKE_SOURCE_DIR}/dpi/dpi_session.cc"
        "${CMAKE_SOURCE_DIR}/dpi/dpi_policy.cc"
        "${CMAKE_SOURCE_DIR}/dpi/dpi_log.cc"
        "${CMAKE_SOURCE_DIR}/dpi/dpi_meter.cc"
        "${CMAKE_SOURCE_DIR}/dpi/dpi_debug.cc"
        "${CMAKE_SOURCE_DIR}/dpi/sig/dpi_hs_search.cc"
        "${CMAKE_SOURCE_DIR}/dpi/sig/dpi_sig.cc"
        "${CMAKE_SOURCE_DIR}/dpi/sig/dpi_hyperscan_common.cc"
        "${CMAKE_SOURCE_DIR}/dpi/sig/dpi_search.cc"
        "${CMAKE_SOURCE_DIR}/dpi/sig/dpi_sigopt_basic.cc"
        "${CMAKE_SOURCE_DIR}/dpi/sig/dpi_sigopt_pcre.cc"
        "${CMAKE_SOURCE_DIR}/dpi/parsers/dpi_http.cc"
        "${CMAKE_SOURCE_DIR}/dpi/parsers/dpi_sqlinjection.cc"
        )
target_link_libraries(dpi hs pcap jansson ${NFQ_LIBRARY})
target_link_libraries(dpi base)


add_library(dpthreads "" base.cc)
target_sources(dpthreads
        PRIVATE
        "${CMAKE_SOURCE_DIR}/dpthreads/dp_ctrl_thread.cc"
        "${CMAKE_SOURCE_DIR}/dpthreads/dp_ctrl_handler.cc"
        "${CMAKE_SOURCE_DIR}/dpthreads/domain_socket_ctrl_dp.cc"
        "${CMAKE_SOURCE_DIR}/dpthreads/domain_socket_ctrl_notify.cc"
        "${CMAKE_SOURCE_DIR}/dpthreads/dp_event_cb.cc"
        "${CMAKE_SOURCE_DIR}/dpthreads/dp_pkt.cc"
        "${CMAKE_SOURCE_DIR}/dpthreads/dp_ring.cc"
        "${CMAKE_SOURCE_DIR}/dpthreads/dp_event_cb.cc"
        )
target_link_libraries(dpthreads base dpi)


add_executable(ardp main.cc)
target_link_libraries(ardp dpi base dpthreads)
