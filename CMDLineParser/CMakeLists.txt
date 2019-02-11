file(GLOB Program_SRCS *.c *.cpp)
file(GLOB Program_HDRS *.h)

add_library(CMDLineParser STATIC ${Program_SRCS} ${Program_HDRS})
target_include_directories(CMDLineParser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

execute_process(
    COMMAND git log --pretty=format:%H -n 1
    OUTPUT_STRIP_TRAILING_WHITESPACE
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_HASH_BIG
    )

execute_process(
    COMMAND git log --pretty=format:%h -n 1
    OUTPUT_STRIP_TRAILING_WHITESPACE
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_HASH_SMALL
    )

execute_process(
    COMMAND git log --pretty=format:%ai -n 1
    OUTPUT_STRIP_TRAILING_WHITESPACE
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_DATA
    )

message(STATUS "Git hash Big:   |" ${GIT_HASH_BIG} "|")
message(STATUS "Git hash Small: |" ${GIT_HASH_SMALL} "|")
message(STATUS "Git hash Date:  |" ${GIT_DATA} "|")

target_compile_options(CMDLineParser PRIVATE "-DGIT_HASH_BIG=${GIT_HASH_BIG}")
target_compile_options(CMDLineParser PRIVATE "-DGIT_HASH_SMALL=${GIT_HASH_SMALL}")
target_compile_options(CMDLineParser PRIVATE "-DGIT_DATA=${GIT_DATA}")

if (WIN32)
  set_property(TARGET CMDLineParser PROPERTY FOLDER "Tools")
endif (WIN32)
