#include <iostream>
#include <fstream>
#include <gflags/gflags.h>
#include <google/protobuf/stubs/common.h>

#include "dumper/streaming_backend.hh"
#include "dumper/text_backend.hh"
#include "dumper/sqlite_backend.hh"

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
    if(FLAGS_mode == "text") {
        TextBackend text_backend(os);
        text_backend.process(is);
    } else if(FLAGS_mode == "sqlite") {
        os.close();
        SqliteBackend sqlite_backend(FLAGS_output);
    } else {
        std::cout << "Could not find backend: " << FLAGS_mode << "\n";
    }

    gflags::ShutDownCommandLineFlags();
    google::protobuf::ShutdownProtobufLibrary();

    return 0;
}
