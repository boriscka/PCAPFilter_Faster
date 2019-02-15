macro(DETECT_X64)
    set(X64 OFF)
    if (MSVC)
        message(STATUS "MSVC build")
        if (CMAKE_CL_64)
            set(X64 ON)
        endif (CMAKE_CL_64)
    else (MSVC)
        message(STATUS "Non-MSVC build")
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(X64 ON)
        endif (CMAKE_SIZEOF_VOID_P EQUAL 8)
        if ("${CMAKE_SIZEOF_VOID_P}" STREQUAL "")
            set(X64 ON)
        endif()
    endif (MSVC)
    if (X64)
        message(STATUS "64-bit architecture")
        set(WIN64 ON)
    else (X64)
        message(STATUS "32-bit architecture")
    endif (X64)
endmacro(DETECT_X64)

macro(ADD_COMMON_DEFINITIONS)
    if (WIN32)
        add_definitions(-DWNT)
    endif (WIN32)
    include_directories(${CMAKE_SOURCE_DIR}/../..)
    if (MSVC)
        add_definitions(-D_CRT_SECURE_NO_WARNINGS)
        add_definitions(-D_SCL_SECURE_NO_WARNINGS)
        add_definitions(-D_USE_MATH_DEFINES)
        add_definitions(-DNOMINMAX)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /bigobj")
#       set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /bigobj")
#       set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /bigobj")
    endif (MSVC)
    if (OCC_LIBRARY_DIR)
        link_directories(${OCC_LIBRARY_DIR})
    endif (OCC_LIBRARY_DIR)
    if (NOT MSVC)
        add_definitions(-DPIC)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -fpermissive")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_STL_STREAM=1 -DHAVE_LIMITS_H=1 -DHAVE_IOSTREAM=1")
    endif (NOT MSVC)
endmacro(ADD_COMMON_DEFINITIONS)

macro(DISPATCH_OPTIONS)
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endmacro(DISPATCH_OPTIONS)