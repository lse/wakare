#include "ptrace_backend.h"
#include "types.h"

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

static csh cap_handle;

// We only read into long aligned buffers because it is easier
void ptrace_read_mem(pid_t child, unsigned long addr, void* buff, unsigned len)
{
    long* wbuff = (long*)buff;

    for(unsigned i = 0; i < len; i += sizeof(long)) {
        *wbuff = ptrace(PTRACE_PEEKTEXT, child, addr+i, NULL);
        wbuff++;
    }
}

static size_t process_instruction(cs_insn* ins, ip_update* branch)
{
    cs_detail* d = ins->detail;
    cs_x86_op ins_arg;

    printf("0x%llx: %s %s\n", ins->address, ins->mnemonic,
            ins->op_str);

    for(int j = 0; j < d->groups_count; j++) {
        switch(d->groups[j]) {
            case X86_GRP_JUMP:
                branch->address = ins->address;

                // A jump has at least an argument
                ins_arg = d->x86.operands[0];

                if(ins_arg.type == X86_OP_IMM) {
                    branch->target_ok = ins_arg.imm;

                    if(ins->id == X86_INS_JMP) {
                        branch->type = INS_JMP;
                    } else {
                        // Conditional branch
                        branch->type = INS_JCC;
                        branch->target_fail = ins->address + ins->size;
                    }
                } else {
                    branch->type = INS_JMP_IND;
                }

                break;
            case X86_GRP_RET:
                branch->address = ins->address;
                branch->type = INS_RET;
                break;
            case X86_GRP_CALL:
                branch->address = ins->address;

                ins_arg = d->x86.operands[0];

                if(ins_arg.type == X86_OP_IMM) {
                    branch->type = INS_CALL;
                    branch->target_ok = ins_arg.imm;
                } else {
                    branch->type = INS_CALL_IND;
                }

                break;
        }
    }
    return ins->size;
}

static ip_update process_bb(pid_t child, unsigned long long rip)
{
    char isnbuf[512];
    size_t count = 0;
    ip_update branch = {0};
    cs_insn *insn;

    branch.type = INS_INVALID;

    while(branch.type == INS_INVALID) {
        // If we have 0 instructions in the buffer we read from rip
        if(count == 0) {
            ptrace_read_mem(child, rip, isnbuf, sizeof(isnbuf));
            count = cs_disasm(cap_handle, isnbuf, sizeof(isnbuf), rip, 0, &insn);
        }

        for(int i = 0; i < count; i++) {
            rip += process_instruction(&insn[i], &branch);

            if(branch.type != INS_INVALID)
                break;
        }

        if(count == 0) { // something weird happened
            abort();
        }

        // As we read all available instructions in the buffer we can
        // set the count to 0.
        count = 0;
    }

    return branch;
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

        ip_update br = process_bb(child, regs.rip);

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
    pid_t child = fork();

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
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &cap_handle) != CS_ERR_OK) {
            fprintf(stderr, "Could not init capstone\n");
            return -1;
        }

        // Enabling instruction details
        cs_option(cap_handle, CS_OPT_DETAIL, CS_OPT_ON);

        int retcode = do_trace(child);

        cs_close(&cap_handle);

        return retcode;
    }

    return 0;
}
