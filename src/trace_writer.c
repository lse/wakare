#include <stdint.h>
#include <stdio.h>

#include "trace_writer.h"

// TODO: Add more error handling

void trace_writer_init(trace_writer* t)
{
    t->edge_count = 0;
    t->map_count  = 0;
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

    uint64_t magic = TRACE_MAGIC;

    fwrite(&magic, sizeof(uint64_t), 1, t->file);

    return 0;
}

int trace_writer_save(trace_writer* t)
{
    if(!t->file)
        return -1;

    size_t size;
    size_t tuple_size = 2 * sizeof(uint64_t);

    fseek(t->file, 0, SEEK_END);
    size = ftell(t->file);

    if(sizeof(uint64_t) >= size) {
        fclose(t->file);
        t->file = NULL;
        return -1;
    }
    
    // Writing the edge count
    fseek(t->file, sizeof(uint64_t), SEEK_SET);
    fwrite(&t->edge_count, sizeof(uint64_t), 1, t->file);
    
    if((t->edge_count + 1) * tuple_size >= size) {
        fclose(t->file);
        t->file = NULL;
        return -1;
    }

    // Writing the map count
    fseek(t->file, (t->edge_count + 1) * tuple_size, SEEK_SET);
    fwrite(&t->map_count, sizeof(uint64_t), 1, t->file);

    fclose(t->file);
    t->file = NULL;

    return 0;
}

void trace_writer_addedge(trace_writer* t, uint64_t from, uint64_t to)
{
    // Writing length header if first call
    if(t->edge_count == 0) {
        fwrite(&t->edge_count, sizeof(uint64_t), 1, t->file);
    }

    uint64_t data[] = {from, to};

    fwrite(data, sizeof(uint64_t), 2, t->file);
    t->edge_count++;
}

void trace_writer_addmap(trace_writer* t, uint64_t from, uint64_t to)
{
    // Writing length header if first call
    if(t->map_count == 0) {
        fwrite(&t->edge_count, sizeof(uint64_t), 1, t->file);
    }

    uint64_t data[] = {from, to};

    fwrite(data, sizeof(uint64_t), 2, t->file);
    t->map_count++;
}
