cmake_minimum_required(VERSION 3.0)
project(tracing)

find_library(LIB_IPT ipt)
find_library(LIB_CAPSTONE capstone)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -fsanitize=address")

set(SOURCES
    src/main.c
    src/disasm.c
    src/ptrace_backend.c
    src/pt_backend.c
    src/trace_writer.c
    src/perf_file.c
    src/utils.c)

include_directories(include)

add_executable(tracer ${SOURCES})
target_link_libraries(tracer
    "${LIB_IPT}"
    "${LIB_CAPSTONE}")
