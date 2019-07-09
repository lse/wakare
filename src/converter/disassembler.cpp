#include <vector>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <capstone/capstone.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "converter/disassembler.hh"

///////////////////// CET Workaround //////////////////////////
struct cet_instruction {
    unsigned size;
    int* pattern;
};

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
static int is_cet(const uint8_t* buff)
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

static size_t process_instruction(cs_insn* ins, CodeBranch& branch)
{
    cs_detail* d = ins->detail;
    cs_x86_op ins_arg;

    //std::printf("0x%llx: %s %s\n", ins->address, ins->mnemonic,
    //        ins->op_str);

    for(int j = 0; j < d->groups_count; j++) {
        switch(d->groups[j]) {
            case X86_GRP_JUMP:
                branch.address = ins->address;

                // A jump has at least an argument
                ins_arg = d->x86.operands[0];

                if(ins_arg.type == X86_OP_IMM) {
                    branch.ok = ins_arg.imm;

                    if(ins->id == X86_INS_JMP) {
                        branch.type = CodeBranchType::Jump;
                    } else {
                        // Conditional branch
                        branch.type = CodeBranchType::CondJump;
                        branch.fail = ins->address + ins->size;
                    }
                } else {
                    branch.type = CodeBranchType::IndJump;
                }

                break;
            case X86_GRP_RET:
                branch.address = ins->address;
                branch.type = CodeBranchType::Return;
                break;
            case X86_GRP_CALL:
                branch.address = ins->address;

                ins_arg = d->x86.operands[0];

                if(ins_arg.type == X86_OP_IMM) {
                    branch.type = CodeBranchType::Call;
                    branch.ok = ins_arg.imm;
                } else {
                    branch.type = CodeBranchType::IndCall;
                }

                break;
        }
    }
    return ins->size;
}
static int align_pagesize(int size)
{
    int ps = getpagesize();
    return (size + ps) & (~(ps - 1));
}

Disassembler::Disassembler() {
    // TODO: Send exception on init error ?
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle_);
    cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
}

size_t Disassembler::mem_read(uint8_t* buff, size_t address, size_t len)
{
    size_t curlen = 0;

    while(curlen < len) {
        // Find page containing address
        DisassemblerPage* page = nullptr;

        for(auto& it : pages_) {
            if((address >= it.start) && (address < it.start + it.size)) {
                page = &it;
                break;
            }
        }

        if(!page)
            break;

        size_t off = address - page->start;
        size_t copylen = 0;

        if(address + len >= page->start + page->size) {
            copylen = len - ((address + len) - (page->start + page->size));
        } else {
            copylen = len;
        }

        std::memcpy(buff + curlen, page->data + off + curlen, copylen);
        curlen += copylen;
    }

    return curlen;
}

int Disassembler::add_page(std::string filename, size_t vaddr, size_t size,
        size_t offset)
{
    int fd = open(filename.c_str(), O_RDONLY);

    if(fd < 0)
        return -1;

    DisassemblerPage page;
    page.start = vaddr;
    page.size = align_pagesize(size);
    page.data = (char*)mmap(0, page.size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
            fd, offset);

    if(!page.data) {
        close(fd);
        return -1;
    }

    pages_.push_back(page);
    close(fd);

    return 0;
}

CodeBranch Disassembler::get_next_branch(size_t ip)
{
    uint8_t insbuf[512];
    CodeBranch branch;
    branch.type = CodeBranchType::Invalid;

    size_t ipcopy = ip;
    cs_insn* ins = cs_malloc(handle_);

    while(branch.type == CodeBranchType::Invalid) {
        // Read error if we read nothing
        size_t len = this->mem_read(insbuf, ip, sizeof(insbuf));

        if(len == 0)
            break;

        const uint8_t* code_ptr = (uint8_t*)insbuf;
        size_t code_len = (size_t)len;

        while(cs_disasm_iter(handle_, &code_ptr, &code_len, &ipcopy, ins)) {
            process_instruction(ins, branch);

            if(branch.type != CodeBranchType::Invalid)
                break;
        }

        if(branch.type != CodeBranchType::Invalid)
            break;

        if(cs_errno(handle_) != CS_ERR_MEM) {
            // We encountered an error before the end of our buffer
            // We check to see if the instruction is a CET one to skip it
            int skip_len = is_cet(code_ptr);

            if(skip_len < 0) {
                cs_free(ins, 1);
                return branch;
            }

            ipcopy += skip_len;
        }
    }

    cs_free(ins, 1);

    return branch;
}

bool Disassembler::is_mapped(size_t address)
{
    for(auto& map : pages_) {
        if(address >= map.start && address < map.start + map.size)
            return true;
    }

    return false;
}
