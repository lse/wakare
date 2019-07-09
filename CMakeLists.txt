cmake_minimum_required(VERSION 3.0)
project(tracing)

option(IPCACHING "Enables branch ip caching" ON)

if(IPCACHING)
    add_compile_definitions(IPCACHING=1)
endif()

find_library(LIB_IPT ipt)
find_library(LIB_CAPSTONE capstone)
find_library(LIB_GFLAGS gflags)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -Wall -fsanitize=address")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS} -ggdb -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "-03 -march=native")

set(CMAKE_CXX_STANDARD 14)

set(TRACER_SOURCES
    src/tracer/main.c
    src/tracer/disasm.c
    src/tracer/ptrace_backend.c
    src/tracer/pt_backend.c
    src/tracer/trace_writer.c
    src/tracer/perf_file.c
    src/tracer/utils.c)

set(CONVERTER_SOURCES
    src/converter/main.cpp
    src/converter/perf_file.cpp
    src/converter/pt_converter.cpp
    src/converter/disassembler.cpp)

add_subdirectory(proto)

add_executable(tracer 
    ${TRACER_SOURCES})

add_executable(converter 
    ${CONVERTER_SOURCES}
    ${PROTO_SRCS}
    ${PROTO_HDRS})

target_include_directories(tracer
    PUBLIC
    include)

target_include_directories(converter
    PUBLIC
    include
    proto)

target_link_libraries(tracer
    "${LIB_IPT}"
    "${LIB_CAPSTONE}")

target_link_libraries(converter
    proto
    "${LIB_IPT}"
    "${LIB_CAPSTONE}"
    "${LIB_GFLAGS}"
    "${PROTOBUF_LIBRARIES}")
