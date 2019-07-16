#include <iostream>
#include <string>
#include <cstdint>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/coded_stream.h>

#include "dumper/streaming_backend.hh"
#include "trace.pb.h"

using namespace google::protobuf::io;

int StreamingBackend::process(std::istream& input_stream)
{
    uint32_t length = 0;
    trace::TraceEvent evt;

    IstreamInputStream istream(&input_stream);
    CodedInputStream coded_stream(&istream);

    while(1) {
        // If we cannot read a varint it must mean that we reached the end
        // TODO: Find a cleaner way of checking for eof
        if(!coded_stream.ReadVarint32(&length))
            break;

        // We have to specify the limit, otherwise protobuf will try to
        // read everything.
        CodedInputStream::Limit lim = coded_stream.PushLimit(length);

        if(!evt.ParseFromCodedStream(&coded_stream)) {
            std::cerr << "Error while parsing message\n";
            break;
        }

        coded_stream.PopLimit(lim);

        // Dispatch
        if(evt.has_branch_evt()) {
            handle_branch(evt.release_branch_evt());
        }

        if(evt.has_mapping_evt()) {
            handle_mapping(evt.release_mapping_evt());
        }
    }

    return 0;
}

