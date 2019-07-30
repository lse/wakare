#ifndef PT_CONVERTER_HH
#define PT_CONVERTER_HH

enum class CodeBranchType {
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

int pt_process(std::string perf_path, std::string binary_path,
        std::string output_path);

#endif
