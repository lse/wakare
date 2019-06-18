#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include <capstone/capstone.h>

#include "ptrace_backend.h"
#include "disasm.h"
#include "types.h"

static disasm* disas;
static pid_t child;

// We only read into long aligned buffers because it is easier
static void ptrace_read_mem(pid_t child, unsigned long addr, void* buff, unsigned len)
{
    long* wbuff = (long*)buff;

    for(unsigned i = 0; i < len; i += sizeof(long)) {
        *wbuff = ptrace(PTRACE_PEEKTEXT, child, addr+i, NULL);
        wbuff++;
    }
}

// Callback function for disassembly interface
static int read_ptrace(disasm* self, uint64_t addr, size_t len, void* buff)
{
    ptrace_read_mem(child, addr, buff, len);

    return len;
}

static int do_trace(pid_t child)
{
    int status = 0;
    struct user_regs_struct regs;
    ip_update next_jump = {0};

    next_jump.type = INS_INVALID;

    pid_t id = waitpid(child, &status, 0);

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEEXIT);

    if(ptrace(PTRACE_SINGLEBLOCK, child, NULL, NULL) < 0) {
        perror("ptrace");
        return -1;
    }

    FILE* out = fopen("trace.data", "wb");

    if(out == NULL) {
        perror("ptrace");
        return -1;
    }

    for(;;) {
        id = waitpid(child, &status, 0);

        if(id < 0)
            break;

        if((status >> 8) == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
            FILE* fp = fopen("trace.map", "wb");

            if(fp == NULL) {
                fprintf(stderr, "could not open map file\n");
            } else {
                /*mempage* page_list = mempages_get(child);

                  for(mempage* it = page_list; it != NULL; it = it->next) {
                  printf("%lx - %lx : %02x\n", it->start, it->end, it->perms);

                  fwrite(&it->start, sizeof(long), 1, fp);
                  fwrite(&it->end, sizeof(long), 1, fp);
                  fwrite(&it->perms, sizeof(char), 1, fp);

                  free(it); // UAF
                  }

                  fclose(fp);*/
            }

            break;
        }

        if(ptrace(PTRACE_GETREGS, child, 0, &regs) < 0) {
            perror("ptrace");
            return -1;
        }

        //printf("0x%llx\n", regs.rip);

        //ip_update br = process_bb(child, regs.rip);
        ip_update br = disasm_next_branch(disas, regs.rip);
        
        if(br.type == INS_INVALID) {
            // We reached an invalid instruction while decoding a besic block
            fclose(out);

            return -1;
        }

        // TODO: Find a way to have proper branches most of the time
        // filter out calls/ret/etc...

        // We check if it is the first jump of the chain
        if(next_jump.type == INS_INVALID) {
            next_jump = br;
        } else {
            if(next_jump.type == INS_JCC) {
                if(regs.rip == next_jump.target_ok) {
                    // Branch taken
                    printf("0x%llx -> 0x%llx\n", next_jump.address, 
                        next_jump.target_ok);
                } else {
                    // Branch not taken
                    printf("0x%llx -> 0x%llx\n", next_jump.address,
                           next_jump.target_fail);
                }
            }
        }

        next_jump = br;

        /*
        if(br.type == INS_JMP) {
            printf("JMP: 0x%llx -> 0x%llx\n", br.address, br.target_ok);
        }

        if(br.type == INS_JCC) {
            printf("JCC: 0x%llx -> 0x%llx (fail 0x%llx)\n",
                    br.address, br.target_ok, br.target_fail);
        }

        if(br.type == INS_CALL) {
            printf("CALL: 0x%llx -> 0x%llx\n", br.address, br.target_ok);
        }

        if(br.type == INS_RET) {
            printf("RET: 0x%llx\n", br.address);
        }
        */

        if(ptrace(PTRACE_SINGLEBLOCK, child, NULL, NULL) < 0) {
            perror("ptrace");
            fclose(out);
            return -1;
        }
    }

    fclose(out);

    return 0;
}

int do_ptrace(char** argv, char** envp)
{
    child = fork();

    if(child == -1) {
        fprintf(stderr, "fork failed\n");
        return -1;
    }


    if(child == 0) {
        // Child process
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            perror("ptrace");
            return -1;
        }

        // Stopping process to let ptrace attach
        raise(SIGSTOP);

        execve(argv[1], &argv[1], envp);
        fprintf(stderr, "execution failed\n");
    } else {
        disas = disasm_new(read_ptrace);

        if(!disas) {
            fprintf(stderr, "Could not init capstone\n");
            return -1;
        }

        int retcode = do_trace(child);
        disasm_free(disas);

        return retcode;
    }

    return 0;
}
