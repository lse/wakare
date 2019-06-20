#ifndef UTILS_H
#define UTILS_H

#define PERM_R 0x1
#define PERM_W 0x2
#define PERM_X 0x4

#include <sys/types.h>
#include <stdint.h>

typedef struct mempage_s {
    long start;
    long end;
    char perms;
    struct mempage_s* next;
} mempage;

mempage* mempages_get(pid_t target);
void mempages_free(mempage* pages);

int align_pagesize(int size);

#endif
