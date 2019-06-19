#ifndef TRACE_WRITER
#define TRACE_WRITER

#include <stdio.h>
#include <stdint.h>

#define TRACE_MAGIC 0xe9cae282c414b97d

typedef struct trace_writer_t {
    uint64_t edge_count;
    uint64_t map_count;
    FILE* file;
} trace_writer;

void trace_writer_init(trace_writer* t);
int trace_writer_begin(trace_writer* t, char* path);
int trace_writer_save(trace_writer* t);

int trace_writer_addedge(trace_writer* t, uint64_t from, uint64_t to);
int trace_writer_addmap(trace_writer* t, uint64_t from, uint64_t to);

#endif
