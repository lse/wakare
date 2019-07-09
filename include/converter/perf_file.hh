#ifndef PERF_FILE_HH
#define PERF_FILE_HH

#include <string>
#include <vector>
#include <cstdint>

#define PERF_FILE_MAGIC "PERFILE2"

// https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/perf.data-file-format.txt#L400
#define PERF_RECORD_AUXTRACE 71
#define PERF_RECORD_FINISHED_ROUND 68

// Structs for header parsing
struct perf_file_section {
    uint64_t offset;
    uint64_t size;
};

struct perf_header {
    char magic[8];
    uint64_t size;
    uint64_t attr_size;
    perf_file_section attrs;
    perf_file_section data;
    perf_file_section event_types;
    uint64_t flags;
    uint64_t flags1[3];
};

// Structs for event parsing
struct perf_record_mmap2 {
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
};

struct perf_record_aux {
    uint64_t aux_offset;
    uint64_t aux_size;
    uint64_t flags;
};

struct perf_record_auxtrace {
    uint64_t size;
    uint64_t offset;
    uint64_t reference;
    uint32_t idx;
    uint32_t tid;
    uint32_t cpu;
    uint32_t reserved__;
};

struct PerfMapping {
    uint64_t start;
    uint64_t size;
    uint64_t offset;
    std::string filename;
};

struct PerfFile {
    std::vector<PerfMapping> maps;
    std::string ptstream;

    PerfFile() = default;

    PerfFile(PerfFile&& src): 
        maps(std::move(src.maps)), 
        ptstream(std::move(src.ptstream))
    {};
};

int parse_perf_data(PerfFile& file, std::string path);

#endif
