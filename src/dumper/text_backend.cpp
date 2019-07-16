#include <iostream>

#include "dumper/text_backend.hh"
#include "trace.pb.h"

static const char* __branch_type_str(trace::BranchEvent* branch)
{
    switch(branch->type()) {
        case trace::BranchType::JUMP:
            return "JUMP   ";
        case trace::BranchType::CONDJUMP:
            return "JCC    ";
        case trace::BranchType::CALL:
            return "CALL   ";
        case trace::BranchType::INDJUMP:
            return "INDJUMP";
        case trace::BranchType::INDCALL:
            return "INDCALL";
    }

    return "INVALID";
}

void TextBackend::handle_branch(trace::BranchEvent* branch)
{
    out_file_ << __branch_type_str(branch) << " "
        << "0x" << std::hex << branch->source() << " -> "
        << "0x" << std::hex << branch->destination() << "\n";
}

void TextBackend::handle_mapping(trace::MappingEvent* mapping)
{
    out_file_ << "MAPPING " << "0x" << std::hex << mapping->start() << " -> "
        << "0x" << std::hex << (mapping->start() + mapping->size()) << " "
        << mapping->filename() << "\n";
}
