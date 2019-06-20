#include <stdio.h>
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
#define RAWDEREF(type, ptr) *(type*)ptr

static void* map_file(char* path)
{
    int fd = open(path, O_RDONLY);
    struct stat statbuf;

    if(fd < 0) {
        fprintf(stderr, "Could not open file\n");
        return NULL;
    }

    if(fstat(fd, &statbuf) < 0) {
        fprintf(stderr, "Could not stat file\n");
        return NULL;
    }

    int aligned_size = align_pagesize(statbuf.st_size);

    char* perf_page = mmap(0, aligned_size, PROT_READ, MAP_PRIVATE, fd, 0);

    return perf_page;
}

int parse_test(char* path)
{
    void* file_ptr = map_file(path);

    if(!file_ptr)
        return -1;

    // Now "parsing"
    perf_header* header = (perf_header*)file_ptr;

    if(strncmp(PERF_FILE_MAGIC, header->magic, strlen(PERF_FILE_MAGIC)) != 0) {
        fprintf(stderr, "Bad magic for perf data\n");
        return -1;
    }

    printf("-------- Attrs --------- \n");
    printf("Offset = 0x%llx\n", header->attrs.offset);
    printf("Size   = 0x%llx\n", header->attrs.size);
    printf("-------- Data --------- \n");
    printf("Offset = 0x%llx\n", header->data.offset);
    printf("Size   = 0x%llx\n", header->data.size);
    printf("-------- Event types --------- \n");
    printf("Offset = 0x%llx\n", header->event_types.offset);
    printf("Size   = 0x%llx\n\n", header->event_types.size);

    void* data_ptr = OFFSETPTR(file_ptr, header->data.offset);
    int i = 0;
    int base_offset = (int)(data_ptr - file_ptr);
    
    while(i < header->data.size) {
        struct perf_event_header* ehd = (struct perf_event_header*)data_ptr;

        /*
        if(ehd->type >= PERF_RECORD_MAX) {
            // Raw event
            printf("RAW 0x%llx: type = %u, size = 0x%llx\n", 
                    base_offset + i, ehd->type, ehd->size);
        } else {
            printf("type:%u 0x%llx: type = %u, size = 0x%llx\n",
                    ehd->type, base_offset + i, ehd->type, ehd->size);
        }
        */

        if(ehd->type == PERF_RECORD_FINISHED_ROUND) {
            break;
        }

        if(ehd->type == PERF_RECORD_MMAP2) {
            /*
             *  struct MMAP2 {
             *      struct perf_event_header header;
             *      u32 pid;
             *      u32 tid;
             *      u64 addr;
             *      u64 len;
             *      u64 pgoff;
             *      u32 maj;
             *      u32 min;
             *      u64 ino;
             *      u64 ino_generation;
             *      u32 prot;
             *      u32 flags;
             *      char[] filename
             *      };
             */
            perf_record_mmap2* mmap2 = OFFSETPTR(data_ptr,
                    sizeof(struct perf_event_header));

            printf("MMAP2 0x%llx - 0x%llx: (pgoff: 0x%llx) '%s'\n",
                    mmap2->addr, mmap2->addr + mmap2->len, 
                    mmap2->pgoff, mmap2->filename);
        }

        if(ehd->type == PERF_RECORD_AUXTRACE) {
            perf_record_auxtrace* auxtrace = OFFSETPTR(data_ptr,
                    sizeof(struct perf_event_header));

            printf("AUXTRACE offset: 0x%llx, size: 0x%llx\n",
                    auxtrace->offset, auxtrace->size);
            
            // AUXTRACE event is followed by actual trace
            // https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/perf.data-file-format.txt#L402
            i += auxtrace->size;

            // We advance the reading pointer by the size of the raw trace
            // as the size for the packet in itself will be updated later
            data_ptr = OFFSETPTR(data_ptr, auxtrace->size);

            unsigned char* d = OFFSETPTR(auxtrace,
                    (sizeof(perf_record_auxtrace)));
        }

        i += ehd->size;
        data_ptr = OFFSETPTR(data_ptr, ehd->size);
    }

    return 0;
}
