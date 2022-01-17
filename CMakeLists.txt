cmake_minimum_required(VERSION 3.20)
project(dsdtools)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb -O0")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -rdynamic")

if (CMAKE_BUILD_TYPE EQUAL "Release")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_SUPPORT_OUTPUT)
    if(IPO_SUPPORTED)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(WARNING "IPO(LTO) is not supported: ${IPO_SUPPORT_OUTPUT}")
    endif()
endif()

##
## Dependencies
##
include(FetchContent)

set(ABSL_PROPAGATE_CXX_STD ON)
FetchContent_Declare(abseil-cpp
    GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
    GIT_TAG        20211102.0
)
FetchContent_MakeAvailable(abseil-cpp)

# target_sources(... ${BACKWARD_ENABLE})
# add_backward(...)
FetchContent_Declare(backward-cpp
    GIT_REPOSITORY https://github.com/bombela/backward-cpp.git
    GIT_TAG        v1.6
)
FetchContent_MakeAvailable(backward-cpp)

##
## Targets
##

add_executable(dsf2raw)
target_sources(dsf2raw PRIVATE dsf2raw.cpp ${BACKWARD_ENABLE})
target_link_libraries(dsf2raw PRIVATE absl::str_format absl::flags_parse)
add_backward(dsf2raw)
