#ifndef DISAS_H
#define DISAS_H

#include <stdint.h>
#include <capstone/capstone.h>

#include "types.h"

struct disasm_s;

typedef int (*read_fn)(struct disasm_s* self, uint64_t addr, size_t len, void* buff);

typedef struct disasm_s {
    csh handle;
    read_fn read;
} disasm;

disasm* disasm_new(read_fn func);
void disasm_free(disasm* dis);
ip_update disasm_next_branch(disasm *self, uint64_t ip);

#endif
