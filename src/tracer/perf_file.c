#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/perf_event.h>

#include "perf_file.h"
#include "utils.h"

#define OFFSETPTR(ptr, off) (void*)(((char*)ptr) + off)

pt_file* pt_file_new()
{
    pt_file* file = malloc(sizeof(pt_file));
    file->maps = NULL;
    file->size = -1;
    file->data = NULL;

    return file;
}

void pt_file_free(pt_file* file)
{
    pt_mapping* it = file->maps;

    while(it != NULL) {
        pt_mapping* next = it->next;
        free(it->filename);
        free(it);
        it = next;
    }
    
    if(file->data != NULL) {
        free(file->data);
    }

    free(file);
}


pt_file* perf_data_parse(char* path)
{
    // Mapping perf file
    int fd = open(path, O_RDONLY);
    struct stat statbuf;

    if(fd < 0) {
        perror("perf");
        close(fd);
        return NULL;
    }

    if(fstat(fd, &statbuf) < 0) {
        perror("perf");
        close(fd);
        return NULL;
    }

    int aligned_size = align_pagesize(statbuf.st_size);
    void* file_ptr = mmap(0, aligned_size, PROT_READ, MAP_PRIVATE, fd, 0);
    
    close(fd);

    if(!file_ptr)
        return NULL;
    
    // Sanity check
    if(statbuf.st_size < sizeof(perf_header)) {
        fprintf(stderr, "File too small\n");
        munmap(file_ptr, aligned_size);
        return NULL;
    }

    // Now "parsing"
    perf_header* header = (perf_header*)file_ptr;
    
    // More sanity checking
    if(strncmp(PERF_FILE_MAGIC, header->magic, strlen(PERF_FILE_MAGIC)) != 0) {
        fprintf(stderr, "Bad magic for perf data\n");
        return NULL;
    }

    if(header->data.offset + header->data.size > statbuf.st_size) {
        fprintf(stderr, "File too small for data section\n");
        munmap(file_ptr, aligned_size);
        return NULL;
    }
    
    void* data_ptr = OFFSETPTR(file_ptr, header->data.offset);
    pt_file* ptfile = pt_file_new();
    bytestream* bs = bytestream_new(BYTESTREAM_CAPACITY);
    int i = 0;

    uint32_t current_tid = 0;
    uint32_t current_cpu = 0;
    
    while(i < header->data.size) {
        struct perf_event_header* ehd = (struct perf_event_header*)data_ptr;

        //if(ehd->type == PERF_RECORD_FINISHED_ROUND) {
        //}

        if(ehd->type == PERF_RECORD_MMAP2) {
            perf_record_mmap2* mmap2 = OFFSETPTR(data_ptr,
                    sizeof(struct perf_event_header));

            pt_mapping* m = malloc(sizeof(pt_mapping));
            m->next = NULL;
            m->start = mmap2->addr;
            m->size = mmap2->len;
            m->offset = mmap2->pgoff;
            m->filename = strdup(mmap2->filename);

            m->next = ptfile->maps;
            ptfile->maps = m;
        }

        if(ehd->type == PERF_RECORD_AUXTRACE) {
            perf_record_auxtrace* auxtrace = OFFSETPTR(data_ptr,
                    sizeof(struct perf_event_header));

            if(current_cpu == 0 && current_tid == 0) {
                current_cpu = auxtrace->cpu;
                current_tid = auxtrace->tid;
            }

            if(current_cpu != auxtrace->cpu || current_tid != auxtrace->tid) {
                fprintf(stderr, "This tool does not support multi cpu/threads traces\n");
                munmap(file_ptr, aligned_size);
                bytestream_free(bs);
                pt_file_free(ptfile);

                return NULL;
            }
            // AUXTRACE event is followed by the actual trace
            // https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/perf.data-file-format.txt#L402
            i += auxtrace->size;

            // We advance the reading pointer by the size of the raw trace
            // as the size for the packet in itself will be at the end of
            // the loop
            data_ptr = OFFSETPTR(data_ptr, auxtrace->size);

            unsigned char* d = OFFSETPTR(auxtrace,
                    (sizeof(perf_record_auxtrace)));

            bytestream_write(bs, d, auxtrace->size);
        }

        i += ehd->size;
        data_ptr = OFFSETPTR(data_ptr, ehd->size);
    }
    
    ptfile->data = bs->data;
    ptfile->size = bs->len;

    free(bs);
    munmap(file_ptr, aligned_size);

    if(ptfile->size == 0) {
        fprintf(stderr, "File did not contain any pt data\n");
        pt_file_free(ptfile);
        return NULL;
    }

    return ptfile;
}
