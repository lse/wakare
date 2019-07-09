find_package(Protobuf REQUIRED)

include_directories(${PROTOBUF_INCLUDE_DIR})
protobuf_generate_cpp(PROTO_SRC PROTO_HEADER trace.proto)

add_library(proto ${PROTO_HEADER} ${PROTO_SRC})
