#ifndef DISASSEMBLER_HH
#define DISASSEMBLER_HH

#include <vector>
#include <cstdint>
#include <iostream>
#include <capstone/capstone.h>
#include <sys/mman.h>

enum CodeBranchType {
    Jump,
    IndJump,
    CondJump,
    Call,
    IndCall,
    Return,
    Invalid
};

struct CodeBranch {
    CodeBranchType type;
    size_t address;
    size_t ok;
    size_t fail;
};

// Virtual page use for disassembly
struct DisassemblerPage {
    size_t start;
    size_t size;
    char* data;
};

class Disassembler {
    public:
    Disassembler();
    ~Disassembler() {
        cs_close(&handle_);

        for(auto& p : pages_)
            munmap(p.data, p.size);
    }

    int add_page(std::string filename, size_t vaddr, size_t size, 
            size_t offset);
    CodeBranch get_next_branch(size_t address);
    size_t mem_read(uint8_t* buff, size_t address, size_t len);
    bool is_mapped(size_t address);

    private:
    csh handle_;
    std::vector<DisassemblerPage> pages_;
};

#endif
