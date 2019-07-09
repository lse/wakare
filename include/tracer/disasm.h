#ifndef DISAS_H
#define DISAS_H

#include <capstone/capstone.h>
#include <stdint.h>

#include "types.h"

typedef struct cache_node_s {
    struct cache_node_s* prev;
    struct cache_node_s* next;
    uint64_t address;
    ip_update data;
} cache_node;

typedef struct branch_cache_s {
    size_t len;
    size_t capacity;
    cache_node* head;
    cache_node* tail;
} branch_cache;

struct disasm_s;

typedef int (*read_fn)(struct disasm_s* self, uint64_t addr, size_t len, void* buff);

typedef struct disasm_s {
    csh handle;
    read_fn read;
    branch_cache cache;
} disasm;

disasm* disasm_new(read_fn func);
void disasm_free(disasm* dis);
ip_update disasm_next_branch(disasm *self, uint64_t ip);

#endif
