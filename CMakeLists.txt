
###################################################################################################

message(STATUS "CMAKE_VERSION='${CMAKE_VERSION}'")
message(STATUS "CMAKE_GENERATOR='${CMAKE_GENERATOR}'")
cmake_minimum_required(VERSION 2.8.11)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(PCAPEditors CXX)

include(Tools)

DETECT_X64()

DISPATCH_OPTIONS()

ADD_COMMON_DEFINITIONS()

include(GiveMePath)

GIVE_ME_PATH()

add_subdirectory(CMDLineParser)
add_subdirectory(PCAP_DiskIO)
add_subdirectory(Program)
