#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// VM definition
typedef enum vmreg_s {
    REG_A,
    REG_B,
    REG_C,
    REG_D,
    REG_MAX
} vmreg;

typedef enum opcode_s {
    OP_NOP,
    OP_ADD,
    OP_MUL,
    OP_SUB,
    OP_MOV,
    OP_PRINT,
    OP_EXIT
} opcode;

typedef enum opmode_s {
    MODE_RR,
    MODE_RI
} opmode;

typedef union oparg_e {
    vmreg reg;
    uint32_t imm;
} oparg;

typedef struct instruction_s {
    opcode op;
    oparg dst;
    oparg src;
} instruction;

typedef struct vm_s {
    uint32_t regs[REG_MAX];
    instruction* code;
    uint32_t ip;
} vm;

// Program computes: print(42 * ((a0 + a1) - 54))
// Input in regs A and B

instruction vmprog[] = {
    {OP_ADD, REG_A, REG_B},
    {OP_MOV, REG_C, 54},
    {OP_MOV, REG_D, 42},
    {OP_SUB, REG_A, REG_C},
    {OP_MUL, REG_D, REG_A},
    {OP_PRINT, REG_D, REG_D},
    {OP_EXIT, REG_A, REG_D}
};

static vm main_vm = {
    .regs = {0},
    .code = vmprog,
    .ip = 0
};

int main(int argc, char** argv)
{
    // We hardcode values for the tests
    main_vm.regs[REG_A] = strtoul("50", 0, 10);
    main_vm.regs[REG_B] = strtoul("12", 0, 10);

    while(1) {
        instruction* ins = &main_vm.code[main_vm.ip];

        switch(ins->op) {
            case OP_ADD:
                main_vm.regs[ins->dst.reg] += main_vm.regs[ins->src.reg];
                break;
            case OP_SUB:
                main_vm.regs[ins->dst.reg] -= main_vm.regs[ins->src.reg];
                break;
            case OP_MUL:
                main_vm.regs[ins->dst.reg] *= main_vm.regs[ins->src.reg];
                break;
            case OP_MOV:
                main_vm.regs[ins->dst.reg] = ins->src.imm;
                break;
            case OP_PRINT:
                printf("%u\n", main_vm.regs[ins->src.reg]);
                break;
            case OP_EXIT:
            case OP_NOP:
            default:
                break;
        }

        if(ins->op == OP_EXIT)
            break;

        main_vm.ip++;
    }

    return 0;
}
