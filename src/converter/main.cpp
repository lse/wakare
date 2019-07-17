#include <iostream>
#include <fstream>
#include <gflags/gflags.h>
#include <google/protobuf/stubs/common.h>

#include "converter/streaming_backend.hh"
#include "converter/text_backend.hh"
#include "converter/sqlite_backend.hh"

DEFINE_string(input, "trace.bin", "Input protobuf file");
DEFINE_string(output, "trace.out", "Processed file path");
DEFINE_string(mode, "text", "Dumping mode (text / sqlite)");

static void handle_text_mode(std::istream& input, std::string outpath)
{
    TextBackend backend;

    if(!backend.setup(outpath))
        return;

    backend.process(input);
}

static void handle_sqlite_mode(std::istream& input, std::string outpath)
{
    SqliteBackend backend;

    if(!backend.setup(outpath))
        return;

    backend.process(input);
}

int main(int argc, char** argv)
{
    gflags::SetUsageMessage("converter -input <file> -output <file> -mode (text/sqlite)");
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    std::ifstream is(FLAGS_input, std::ios::binary);

    if(!is) {
        std::cerr << "Could not open input file: " << FLAGS_input << "\n";
        return 1;
    }

    // Processing part
    if(FLAGS_mode == "text") {
        handle_text_mode(is, FLAGS_output);
    } else if(FLAGS_mode == "sqlite") {
        handle_sqlite_mode(is, FLAGS_output);
    } else {
        std::cout << "Could not find backend: " << FLAGS_mode << "\n";
    }

    gflags::ShutDownCommandLineFlags();
    google::protobuf::ShutdownProtobufLibrary();

    return 0;
}
