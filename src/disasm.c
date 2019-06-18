#include <stdio.h>
#include <stdlib.h>
#include <capstone/capstone.h>

#include "disasm.h"

//////////////// CET Instructions workaround /////////////////
typedef struct cet_instruction_s {
    unsigned size;
    int* pattern;
} cet_instruction;

int pattern_incsspd[]     = {0xf3, 0x0f, 0xae, -1};
int pattern_incsspq[]     = {0xf3, -1, 0x0f, 0xae, -1};
int pattern_rdsspd[]      = {0xf3, 0x0f, 0x1e, -1};
int pattern_rdsspq[]      = {0xf3, -1, 0x0f, 0x1e, -1};
int pattern_saveprevssp[] = {0xf3, 0x0f, 0x01, 0xea};
int pattern_rstorssp[]    = {0xf3, 0x0f, 0x01, -1};
int pattern_wrssd[]       = {0x0f, 0x38, 0xf6};
int pattern_wrssq[]       = {-1, 0x0f, 0x38, 0xf6};
int pattern_wrussd[]      = {0x66, 0x0f, 0x38, 0xf5};
int pattern_wrussq[]      = {0x66, -1, 0x0f, 0x38, 0xf5};
int pattern_setssbsy[]    = {0xf3, 0x0f, 0x01, 0xe8};
int pattern_clrssbsy[]    = {0xf3, 0x0f, 0xae, -1};

cet_instruction new_instructions[] = {
    {
        // INCSSPD
        .size = 4,
        .pattern = pattern_incsspd
    },
    {
        // INCSSPQ
        .size = 5,
        .pattern = pattern_incsspq
    },
    {
        // RDSSPD
        .size = 4,
        .pattern = pattern_rdsspd
    },
    {
        // RDSSPQ
        .size = 5,
        .pattern = pattern_rdsspq
    },
    {
        // SAVEPREVSSP
        .size = 4,
        .pattern = pattern_saveprevssp
    },
    {
        // RSTORSSP
        .size = 4,
        .pattern = pattern_rstorssp
    },
    {
        // WRSSD
        .size = 3,
        .pattern = pattern_wrssd
    },
    {
        // WRSSQ
        .size = 4,
        .pattern = pattern_wrssq
    },
    {
        // WRUSSD
        .size = 4,
        .pattern = pattern_wrussd
    },
    {
        // WRUSSQ
        .size = 5,
        .pattern = pattern_wrussq
    },
    {
        // SETSSBSY
        .size = 4,
        .pattern = pattern_setssbsy
    },
    {
        // CLRSSBSY
        .size = 4,
        .pattern = pattern_clrssbsy
    },
    {
        .size = 0,
        .pattern = NULL
    }
};

// Checks if the unsupported instruction is an intel CET
// instruction (RDSSP, INCSSP, etc...)
//
// returns the length on success and -1 if the instruction
// is truly invalid
static int is_cet(unsigned char* buff)
{
    cet_instruction* it = new_instructions;

    while(it->pattern != NULL) {
        int valid = 1;

        for(int i = 0; i < it->size; i++) {
            // Pattern -1 is a wildcard
            if(it->pattern[i] == -1)
                continue;

            if(it->pattern[i] != (int)buff[i]) {
                valid = 0;
                break;
            }
        }

        if(valid)
            return it->size;

        it++;
    }

    return -1;
}

/////////// END CET workaround /////////////////

static size_t process_instruction(cs_insn* ins, ip_update* branch)
{
    cs_detail* d = ins->detail;
    cs_x86_op ins_arg;

    //printf("0x%llx: %s %s\n", ins->address, ins->mnemonic,
    //        ins->op_str);

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

ip_update disasm_next_branch(disasm* self, uint64_t ip)
{
    unsigned char isnbuf[512];
    int count = -1;
    ip_update branch = {0};
    cs_insn *insn;

    branch.type = INS_INVALID;

    while(branch.type == INS_INVALID) {
        // When count equals -1 -> buffer empty / processed
        if(count == -1) {
            self->read(self, ip, sizeof(isnbuf), isnbuf);
            count = cs_disasm(self->handle, isnbuf, sizeof(isnbuf), ip, 0, &insn);
        }
        
        // There was an error. Check if it is an intel CET instruction
        // (INSSP, RDSSP, ...)
        if(count == 0) {
            int skip_size = is_cet(isnbuf);

            if(skip_size == -1) {
                fprintf(stderr, "Invalid instruction 0x%llx ", ip);

                for(int i = 0; i < 16; i++) {
                    fprintf(stderr, "%02x ", isnbuf[i]);
                }

                fprintf(stderr, "\n");
                
                // As the current type is INS_INVALID
                // the error will propagate to the call site.
                return branch;
            }

            // We skip the cet instruction
            ip += skip_size;
        }

        for(int i = 0; i < count; i++) {
            ip += process_instruction(&insn[i], &branch);

            if(branch.type != INS_INVALID)
                break;
        }

        // As we read all available instructions in the buffer we can
        // set the count to -1.
        count = -1;
    }

    return branch;
}

disasm* disasm_new(read_fn fn)
{
    disasm* d = malloc(sizeof(disasm));
    d->read = fn;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &d->handle) != CS_ERR_OK) {
        return NULL;
    }

    cs_option(d->handle, CS_OPT_DETAIL, CS_OPT_ON);

    return d;
}

void disasm_free(disasm* dis)
{
    cs_close(&dis->handle);
    free(dis);
}
