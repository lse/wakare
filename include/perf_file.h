#ifndef PERF_FILE_H
#define PERF_FILE_H

#include <stdint.h>

#define PERF_FILE_MAGIC "PERFILE2"

// https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/perf.data-file-format.txt#L400
#define PERF_RECORD_AUXTRACE 71
#define PERF_RECORD_FINISHED_ROUND 68

// Structs for header parsing
typedef struct perf_file_section_s {
    uint64_t offset;
    uint64_t size;
} perf_file_section;

typedef struct perf_header_s {
    char magic[8];
    uint64_t size;
    uint64_t attr_size;
    perf_file_section attrs;
    perf_file_section data;
    perf_file_section event_types;
    uint64_t flags;
    uint64_t flags1[3];
} perf_header;

// Structs for event parsing
typedef struct perf_record_mmap2_s {
    uint32_t pid;
    uint32_t tid;
    uint64_t addr;
    uint64_t len;
    uint64_t pgoff;
    uint32_t maj;
    uint32_t min;
    uint64_t ino;
    uint64_t ino_generation;
    uint32_t prot;
    uint32_t flags;
    char filename[];
} perf_record_mmap2;

typedef struct perf_record_aux_s {
    uint64_t aux_offset;
    uint64_t aux_size;
    uint64_t flags;
} perf_record_aux;

typedef struct perf_record_auxtrace_s {
    uint64_t size;
    uint64_t offset;
    uint64_t reference;
    uint32_t idx;
    uint32_t tid;
    uint32_t cpu;
    uint32_t reserved__;
} perf_record_auxtrace;

int parse_test(char* path);

#endif
