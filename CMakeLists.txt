cmake_minimum_required(VERSION 3.0)
project(tracing)

option(IPCACHING "Enables branch ip caching" ON)

if(IPCACHING)
    add_compile_definitions(IPCACHING=1)
endif()

find_library(LIB_IPT ipt)
find_library(LIB_CAPSTONE capstone)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -Wall -fsanitize=address")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native")

set(TRACER_SOURCES
    src/tracer/main.c
    src/tracer/disasm.c
    src/tracer/ptrace_backend.c
    src/tracer/pt_backend.c
    src/tracer/trace_writer.c
    src/tracer/perf_file.c
    src/tracer/utils.c)

set(CONVERTER_SOURCES
    src/converter/main.cpp)

include_directories(include)

add_executable(tracer ${TRACER_SOURCES})
add_executable(converter ${CONVERTER_SOURCES})

target_link_libraries(tracer
    "${LIB_IPT}"
    "${LIB_CAPSTONE}")
