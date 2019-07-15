#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <fcntl.h>
#include <unistd.h>

#include "extractor/perf_file.hh"

static int align_pagesize(int size)
{
    int ps = getpagesize();
    return (size + ps) & (~(ps - 1));
}

static void* map_file(const char* path, size_t& size)
{
    int fd = open(path, O_RDONLY);

    if(fd < 0)
        return nullptr;

    
    struct stat statbuf;

    if(fstat(fd, &statbuf) < 0) {
        close(fd);
        return nullptr;
    }

    size = align_pagesize(statbuf.st_size);
    
    void* res = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    return res;
}

int parse_perf_data(PerfFile& file, std::string path)
{
    std::stringstream ptdata;
    size_t file_size = 0;

    char* file_ptr = (char*)map_file(path.c_str(), file_size);

    if(!file_ptr) {
        std::cerr << "Could not open file: " << path << "\n";
        return -1;
    }

    if(file_size < sizeof(perf_header)) {
        std::cerr << "File too small\n";
        return -1;
    }

    perf_header* header = (perf_header*)file_ptr;

    if(std::strncmp(PERF_FILE_MAGIC, header->magic, 
                std::strlen(PERF_FILE_MAGIC)) != 0) {
        std::cerr << "Wrong magic\n";
        munmap(file_ptr, file_size);
        return -1;
    }
    
    if(header->data.offset + header->data.size > file_size) {
        std::cerr << "File too small for data section\n";
        munmap(file_ptr, file_size);
        return -1;
    }

    uint32_t current_tid = 0;
    uint32_t current_cpu = 0;
    char* data_ptr = file_ptr + header->data.offset;
    int i = 0;

    while(i < header->data.size) {
        struct perf_event_header* ehd = (struct perf_event_header*)data_ptr;

        if(ehd->type == PERF_RECORD_MMAP2) {
            perf_record_mmap2* mmap2 = (perf_record_mmap2*)(ehd + 1);

            PerfMapping m;
            m.start = mmap2->addr;
            m.size = mmap2->len;
            m.offset = mmap2->pgoff;
            m.filename = std::string(mmap2->filename);

            file.maps.push_back(m);
        }

        if(ehd->type == PERF_RECORD_AUXTRACE) {
            perf_record_auxtrace* aux = (perf_record_auxtrace*)(ehd + 1);

            if(current_cpu == 0 && current_tid == 0) {
                current_cpu = aux->cpu;
                current_tid = aux->tid;
            }

            if(current_cpu != aux->cpu || current_tid != aux->tid) {
                std::cerr << "This tool doesn't sypport multiple cpu/threads\n";
                munmap(file_ptr, file_size);

                return -1;
            }

            i += aux->size;
            data_ptr = data_ptr + aux->size;
            ptdata.write(reinterpret_cast<char*>(aux + 1), aux->size);
        }

        i += ehd->size;
        data_ptr += ehd->size;
    }

    file.ptstream = ptdata.str();

    return 0;
}
