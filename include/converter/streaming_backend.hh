#ifndef STREAMING_BACKEND_HH
#define STREAMING_BACKEND_HH

#include <iostream>

#include "trace.pb.h"

class StreamingBackend {
    public:
    StreamingBackend() = default;
    int process(std::istream& input_stream);

    virtual bool setup(std::string outpath) = 0;
    virtual void handle_branch(trace::BranchEvent* branch) = 0;
    virtual void handle_mapping(trace::MappingEvent* mapping) = 0;
    virtual void handle_hitcount(trace::HitcountEvent* hit) = 0;
};

#endif
