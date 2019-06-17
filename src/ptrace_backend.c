#include "ptrace_backend.h"

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

// We only read into long aligned buffers because it is easier
void ptrace_read_mem(pid_t child, unsigned long addr, void* buff, unsigned len)
{
    long* wbuff = (long*)buff;
    
    for(unsigned i = 0; i < len; i += sizeof(long)) {
        *wbuff = ptrace(PTRACE_PEEKTEXT, child, addr+i, NULL);
        wbuff++;
    }

}

/*
 * Only a test function for now
 */
void disassemble_bb(pid_t child, unsigned long long rip) {
    csh handle;
    cs_insn *insn;
    char isnbuf[512];
    size_t count = 0;

    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);

    // Enable details on instructions
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
   
    ptrace_read_mem(child, rip, isnbuf, sizeof(isnbuf));
    count = cs_disasm(handle, isnbuf, sizeof(isnbuf), rip, 0, &insn);

    for(int i = 0; i < count; i++) {
        cs_insn ins = insn[i];
        cs_detail* d = ins.detail;

        int should_exit = 0;

        printf("0x%llx: %s %s\n", ins.address, ins.mnemonic,
                ins.op_str);

        if(d) {
            for(int j = 0; j < d->groups_count; j++) {
                if(d->groups[j] == X86_GRP_JUMP)
                    should_exit = 1;
            }
        }

        if(should_exit)
            break;
    }
}

static int do_trace(pid_t child)
{
    int status = 0;
    unsigned long long last_rip = 0;
    struct user_regs_struct regs;

    pid_t id = waitpid(child, &status, 0);

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEEXIT);

    if(ptrace(PTRACE_SINGLEBLOCK, child, NULL, NULL) < 0) {
        perror("ptrace-backend");
        return -1;
    }

    FILE* out = fopen("trace.data", "wb");

    if(out == NULL) {
        perror("ptrace-backend");
        return -1;
    }

    for(;;) {
        id = waitpid(child, &status, 0);

        if(id < 0)
            break;

        if((status >> 8) == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
            FILE* fp = fopen("trace.map", "wb");

            if(fp == NULL) {
                fprintf(stderr, "ptrace-backend: could not open map file\n");
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
            perror("ptrace-backend");
            return -1;
        }

        //printf("0x%llx\n", regs.rip);

        if(regs.rip == 0x401106) {
            disassemble_bb(child, regs.rip);
        }

        if(ptrace(PTRACE_SINGLEBLOCK, child, NULL, NULL) < 0) {
            perror("ptrace-backend");
            fclose(out);
            return -1;
        }
    }

    fclose(out);

    return 0;
}

int do_ptrace(char** argv, char** envp)
{
    pid_t child = fork();

    if(child == -1) {
        fprintf(stderr, "ptrace-backend: fork failed\n");
        return -1;
    }


    if(child == 0) {
        // Child process
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            perror("ptrace-backend");
            return -1;
        }

        // Stopping process to let ptrace attach
        raise(SIGSTOP);

        execve(argv[1], &argv[1], envp);
        fprintf(stderr, "ptrace-backend: execution failed\n");
    } else {
        // Parent process
        return do_trace(child);
    }

    return 0;
}
