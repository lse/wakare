#include <iostream>
#include <fstream>
#include <cstdint>

#include "converter/text_backend.hh"
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

bool TextBackend::setup(std::string path)
{
    out_file_.open(path, std::ios::binary);
    if(!out_file_) {
        std::cerr << "Could not open file \"" << path << "\"\n";
        return false;
    }

    return true;
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
        << "0x" << (mapping->start() + mapping->size()) << " "
        << mapping->filename() << "\n";
}

void TextBackend::handle_hitcount(trace::HitcountEvent* hit)
{
    out_file_ << "BBHIT   " << "0x" << std::hex << hit->address() << " "
        << std::dec << hit->count() << "\n";
}
