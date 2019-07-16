#ifndef STREAMING_BACKEND_HH
#define STREAMING_BACKEND_HH

#include <iostream>

#include "trace.pb.h"

class StreamingBackend {
    public:
    StreamingBackend() = default;
    int process(std::istream& input_stream);

    virtual void handle_branch(trace::BranchEvent* branch) = 0;
    virtual void handle_mapping(trace::MappingEvent* mapping) = 0;
};

#endif
