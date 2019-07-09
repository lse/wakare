#ifndef TRACE_WRITER
#define TRACE_WRITER

#include <stdio.h>
#include <stdint.h>

#define TRACE_MAGIC "TRACEOUT"

typedef struct trace_writer_t {
    uint64_t edge_count;
    uint64_t map_count;
    FILE* file;
} trace_writer;

typedef struct trace_event_jump_t {
    uint64_t from;
    uint64_t to;
} trace_event_jump;

typedef struct trace_event_mmap_t {
    uint64_t start;
    uint64_t size;
    uint64_t offset;
    char filename[];
} trace_event_mmap;

typedef enum trace_event_type_t {
    trace_ev_jump,
    trace_ev_mmap
} trace_event_type;

typedef struct trace_event_t {
    trace_event_type type;
    size_t size;

    union {
        trace_event_mmap mmap;
        trace_event_jump jump;
    };
} trace_event;

void trace_writer_init(trace_writer* t);
int trace_writer_begin(trace_writer* t, char* path);
int trace_writer_end(trace_writer* t);

void trace_write_mmap(trace_writer* t, uint64_t start, uint64_t len,
        uint64_t off, char* filename);

void trace_write_jump(trace_writer* t, uint64_t from, uint64_t to);

#endif
