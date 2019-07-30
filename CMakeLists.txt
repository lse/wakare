cmake_minimum_required(VERSION 3.0)
project(wakare)

include(FindProtobuf)

find_library(LIB_IPT ipt)
find_library(LIB_CAPSTONE capstone)
find_library(LIB_GFLAGS gflags)
find_library(LIB_SQLITE sqlite3)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS} -ggdb -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native")

set(CMAKE_CXX_STANDARD 14)

set(EXTRACTOR_SOURCES
    src/extractor/main.cpp
    src/extractor/perf_file.cpp
    src/extractor/pt_extractor.cpp)

set(CONVERTER_SOURCES
    src/converter/main.cpp
    src/converter/streaming_backend.cpp
    src/converter/text_backend.cpp
    src/converter/sqlite_backend.cpp)

add_subdirectory(proto)

add_executable(wakare-extractor
    ${EXTRACTOR_SOURCES}
    ${PROTO_SRCS}
    ${PROTO_HDRS})

add_executable(wakare-converter
    ${CONVERTER_SOURCES}
    ${PROTO_SRCS}
    ${PROTO_HDRS})

target_include_directories(wakare-extractor
    PUBLIC
    include
    proto)

target_include_directories(wakare-converter
    PUBLIC
    include
    proto)

target_link_libraries(wakare-extractor
    proto
    "${LIB_IPT}"
    "${LIB_CAPSTONE}"
    "${LIB_GFLAGS}"
    "${PROTOBUF_LIBRARY}")

target_link_libraries(wakare-converter
    proto
    "${PROTOBUF_LIBRARY}"
    "${LIB_GFLAGS}"
    "${LIB_SQLITE}")
