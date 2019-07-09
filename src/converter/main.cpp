#include <gflags/gflags.h>
#include "converter/pt_converter.hh"

DEFINE_string(input, "perf.data", "Input perf.data file");
DEFINE_string(binary, "a.out", "Target binary");
DEFINE_string(output, "trace.bin", "Output file for the trace");

int main(int argc, char** argv)
{
    gflags::SetUsageMessage("converter --perf_file <perf.data> --binary <bin>");
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    int status =  pt_process(FLAGS_input, FLAGS_binary, FLAGS_output);
    gflags::ShutDownCommandLineFlags();

    return status;
}
