cmake_minimum_required(VERSION 3.16)
project(network-monitor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------
# Find dynamic ncurses
# -----------------------------------------
find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

# -----------------------------------------
# Find dynamic libpcap
# -----------------------------------------
find_library(PCAP_LIB pcap REQUIRED)

# -----------------------------------------
# Build
# -----------------------------------------
add_executable(network-monitor
    src/main.cpp
    src/ui.cpp
)

# -----------------------------------------
# Link
# -----------------------------------------
target_link_libraries(network-monitor
    PRIVATE
        ${CURSES_LIBRARIES}
        ${PCAP_LIB}
)
