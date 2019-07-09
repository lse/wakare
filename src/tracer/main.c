#include <stdio.h>
#include <string.h>

#include "ptrace_backend.h"
#include "pt_backend.h"

char* usage = "usage: %s [mode] args...\n\n"\
               "mode\n"\
               "  ptrace <command line>                 Gather data through ptrace tracing\n"\
               "  pt     <perf.data file> <executable>  Parses pt traces from perf data file\n";

int main(int argc, char** argv, char** envp)
{
    if(argc < 3) {
        printf(usage, argv[0]);
        return 1;
    }

    if(strcmp(argv[1], "ptrace") == 0) {
        return do_ptrace_trace(&argv[2], envp);
    } else if(strcmp(argv[1], "pt") == 0) {
        if(argc < 4) {
            printf(usage, argv[0]);
            return 1;
        }

        return do_pt_trace(&argv[2], envp);
    } else {
        printf("Invalid backend '%s'\n", argv[1]);
        printf("Valid backends are 'ptrace' and 'pt'\n");

        return 1;
    }

    return 0;
}
