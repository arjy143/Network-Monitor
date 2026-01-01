cmake_minimum_required(VERSION 3.16)
project(network-monitor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------
# Find dependencies
# -----------------------------------------

# ncurses
find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

# libpcap
find_library(PCAP_LIB pcap REQUIRED)

# pthreads
find_package(Threads REQUIRED)

# -----------------------------------------
# Build
# -----------------------------------------
add_executable(network-monitor
    src/main.cpp
    src/app.cpp
    src/ui.cpp
    src/capture.cpp
    src/packet.cpp
    src/packet_store.cpp
    src/panel.cpp
    src/sidebar.cpp
    src/panels/packet_list.cpp
    src/panels/stats.cpp
    src/panels/graph.cpp
    src/panels/detail.cpp
)

# -----------------------------------------
# Link
# -----------------------------------------
target_link_libraries(network-monitor
    PRIVATE
        ${CURSES_LIBRARIES}
        ${PCAP_LIB}
        Threads::Threads
)

# -----------------------------------------
# Compiler warnings
# -----------------------------------------
target_compile_options(network-monitor PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)
