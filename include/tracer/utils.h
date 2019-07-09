#ifndef UTILS_H
#define UTILS_H

#define PERM_R 0x1
#define PERM_W 0x2
#define PERM_X 0x4

#define BYTESTREAM_CAPACITY 256

#include <sys/types.h>
#include <stdint.h>

typedef struct mempage_s {
    long start;
    long end;
    char perms;
    struct mempage_s* next;
} mempage;

typedef struct bytestream_s {
    size_t capacity;
    size_t len;
    void* data;
} bytestream;

mempage* mempages_get(pid_t target);
void mempages_free(mempage* pages);

int align_pagesize(int size);

bytestream* bytestream_new(size_t capacity);
void bytestream_free(bytestream* bs);
void bytestream_write(bytestream* bs, void* data, size_t size);
#endif
