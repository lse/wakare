#include <iostream>
#include <fstream>
#include <gflags/gflags.h>

#include "dumper/streaming_backend.hh"
#include "dumper/text_backend.hh"

DEFINE_string(input, "trace.bin", "Input protobuf file");
DEFINE_string(output, "trace.out", "Processed file path");
DEFINE_string(mode, "text", "Dumping mode (text / sqlite)");

int main(int argc, char** argv)
{
    gflags::SetUsageMessage("dumper -input <file> -output <file> -mode (text/sqlite)");
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    std::ifstream is(FLAGS_input, std::ios::binary);

    if(!is) {
        std::cerr << "Could not open input file: " << FLAGS_input << "\n";
        return 1;
    }
    
    std::ofstream os(FLAGS_output, std::ios::binary);

    if(!os) {
        std::cerr << "Could not open output file: " << FLAGS_output << "\n";
        return 1;
    }

    // Processing part
    StreamingBackend* backend = nullptr;

    if(FLAGS_mode == "text") {
        backend = new TextBackend(os);
    } else if(FLAGS_mode == "sqlite") {
        std::cout << "Not implemented\n";
    } else {
        std::cout << "Could not find backend: " << FLAGS_mode << "\n";
    }

    if(backend) {
        backend->process(is);
        delete backend;
    }

    gflags::ShutDownCommandLineFlags();

    return 0;
}
