#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tracer/trace.h"

// TODO: Add more error handling

void trace_writer_init(trace_writer* t)
{
    t->file = NULL;
}

int trace_writer_begin(trace_writer* t, char* path)
{
    // A file is already open
    if(t->file != NULL) {
        return -1;
    }

    t->file = fopen(path, "wb");
    
    // Could not open trace file
    if(!t->file)
        return -1;

    fwrite(TRACE_MAGIC, strlen(TRACE_MAGIC), 1, t->file);

    return 0;
}

void trace_writer_close(trace_writer* t)
{
    fclose(t->file);
}

void trace_write_jump(trace_writer* t, uint64_t from, uint64_t to)
{
    trace_event evt = {0};

    evt.type = trace_ev_jump;
    evt.size = sizeof(trace_event);
    evt.jump.from = from;
    evt.jump.to = to;

    fwrite(&evt, sizeof(trace_event), 1, t->file);
}

void trace_write_mmap(trace_writer* t, uint64_t start, uint64_t len,
        uint64_t off, char* filename)
{
    trace_event evt = {0};
    int name_len = strlen(filename);

    evt.type = trace_ev_mmap;
    evt.mmap.start = start;
    evt.mmap.size = len;
    evt.mmap.offset = off;
    evt.size = sizeof(trace_event) + name_len + 1; // + 1 for null byte

    fwrite(&evt, sizeof(trace_event), 1, t->file);
    fwrite(filename, name_len + 1, 1, t->file);
}
