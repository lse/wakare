#ifndef TEXT_BACKEND_HH
#define TEXT_BACKEND_HH

#include <iostream>
#include <cstdint>

#include "converter/streaming_backend.hh"
#include "trace.pb.h"

class TextBackend: public StreamingBackend {
    public:
    TextBackend(std::ostream& out_stream): out_file_(out_stream) {};

    void handle_branch(trace::BranchEvent* branch) override;
    void handle_mapping(trace::MappingEvent* mapping) override;
    void handle_hitcount(trace::HitcountEvent* hit) override;

    private:
    std::ostream& out_file_;
};

#endif
