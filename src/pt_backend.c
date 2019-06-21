#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "pt_backend.h"
#include "perf_file.h"

static int do_trace(char* full_path) {
    pt_file* ptfile = perf_data_parse(PT_TEMP_FILE);

    if(!ptfile)
        return -1;

    if(ptfile->size == -1 || ptfile->data == NULL) {
        fprintf(stderr, "File didn't contain pt data\n");
        pt_file_free(ptfile);
        return -1;
    }

    pt_mapping* target = NULL;
    
    // We try to find our executable mappings
    for(pt_mapping* it = ptfile->maps; it != NULL; it = it->next) {
        //printf("0x%llx - 0x%llx (real offset: 0x%llx)\t %s\n",
        //        it->start, it->start + it->size, it->offset, it->filename);
        
        if(strcmp(full_path, it->filename) == 0)
            target = it;
    }

    if(!target) {
        fprintf(stderr, "Could not find mappings for file '%s'\n", full_path);
        pt_file_free(ptfile);
        return -1;
    }

    pt_file_free(ptfile);

    return 0;
}

int do_pt_trace(char** argv, char** envp)
{
    // Check if pt is supported (/sys/devices/intel_pt)
    if(access("/sys/devices/intel_pt", F_OK) != 0) {
        fprintf(stderr, "This device does not support intel_pt\n");
        return -1;
    }

    // Check if perf is installed
    if(access("/usr/bin/perf", F_OK) != 0) {
        fprintf(stderr, "Please install perf at /usr/bin/perf\n");
        return -1;
    }

    // Check if the executable is available
    if(access(argv[0], F_OK) != 0) {
        fprintf(stderr, "Could not find executable '%s'\n", argv[0]);
        return -1;
    }

    char* full_path = malloc(PATH_MAX);

    if(!realpath(argv[0], full_path)) {
        fprintf(stderr, "Could not get full path of '%s'\n", argv[0]);
        free(full_path);
        return -1;
    }
    
    // We disable timing information (tsc, mtc) because we don't need it
    // and we also disable return compression (noretcomp) to get a trace 
    // that is easier to process (no need to keep a virtual return stack)
    char* perf_cmd[] = {
        "/usr/bin/perf", "record", "-e", 
        "intel_pt/tsc=0,mtc=0,noretcomp=1/u",
        "-o", PT_TEMP_FILE
    };
    
    int perf_cmd_len = sizeof(perf_cmd) / sizeof(char*);
    int usr_cmd_len = 0;

    for(int i = 0; argv[i] != NULL; i++)
        usr_cmd_len++;

    int final_cmd_len = (usr_cmd_len + 1 + perf_cmd_len);
    char** combined_argv = malloc(sizeof(char*) * final_cmd_len);
    
    // Combining argvs
    for(int i = 0; i < (final_cmd_len - 1); i++) {
        if(i < perf_cmd_len) {
            combined_argv[i] = perf_cmd[i];
        } else {
            combined_argv[i] = argv[i - perf_cmd_len];
        }
    }

    combined_argv[final_cmd_len - 1] = 0;

    // Now executing perf command
    pid_t child = fork();

    if(child == -1) {
        fprintf(stderr, "Fork failed\n");
        free(full_path);
        return -1;
    }

    if(child == 0) {
        execve(combined_argv[0], combined_argv, envp);
        fprintf(stderr, "There was an error executing perf\n");
        perror("execve");
        exit(-1);
    }
    
    // Now waiting for process to finish
    int status = 0;

    while(1) {
        pid_t id = waitpid(child, &status, 0);

        if(id < 0) {
            fprintf(stderr, "watipid() failed\n");
            perror("waitpid");

            free(full_path);
            return -1;
        }
        
        if(WIFEXITED(status) || WIFSIGNALED(status) ) {
            break;
        }
    }

    int trace_status = do_trace(full_path);
    free(full_path);
    free(combined_argv);

    return trace_status;
}
