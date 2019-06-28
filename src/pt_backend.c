#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <intel-pt.h>

#include "pt_backend.h"
#include "perf_file.h"
#include "disasm.h"
#include "utils.h"
#include "trace_writer.h"

// Section about traced mappings and associated helper functions
typedef struct mapped_page_s {
    struct mapped_page_s* next;
    uint64_t start;
    uint64_t len;
    void* data;
} mapped_page;

static mapped_page* mpp_add_section(mapped_page* pages, char* filename, 
        uint64_t vaddr, uint64_t len, uint64_t off)
{
    int fd = open(filename, O_RDONLY);

    if(fd < 0)
        return NULL;

    void* mem = mmap(NULL, align_pagesize(len), PROT_READ | PROT_WRITE,
            MAP_PRIVATE, fd, off);

    close(fd);
    
    if(mem == NULL)
        return NULL;

    mapped_page* page = malloc(sizeof(mapped_page));
    page->start = vaddr;
    page->len = align_pagesize(len);
    page->data = mem;
    page->next = pages;

    return page;
}

static void mpp_free(mapped_page* pages)
{
    mapped_page* it = pages;

    while(it != NULL) {
        mapped_page* next = it->next;
        munmap(it->data, it->len);
        free(it);
        it = next;
    }
}

static int mpp_inrange(mapped_page* pages, uint64_t addr)
{
    for(mapped_page* it = pages; it != NULL; it = it->next) {
        if(addr >= it->start && addr < (it->start + it->len)) {
            return 1;
        }
    }

    return 0;
}
// End mapping api

static disasm* disas;
static mapped_page* traced_pages;

static int read_pt(disasm* self, uint64_t addr, size_t len, void* buff)
{
    // Getting target page
    for(mapped_page* it = traced_pages; it != NULL; it = it->next) {
        if(addr > it->start && addr < (it->start + it->len)) {
            int readcnt = len;

            // Compute real offset in the mapped area
            char* dataptr = (char*)it->data + (addr - it->start);

            if(addr + len > (it->start + it->len)) {
                readcnt = (it->start + it->len) - addr;
            }

            memcpy(buff, dataptr, readcnt);

            return readcnt;
        }
    }

    return -1;
}

// Fallback method to continue processing the trace even when some
// data is lost. We use the next FUP packet as a starting point.
static uint64_t pkt_next_psb(struct pt_packet_decoder* d, uint64_t off)
{
    struct pt_packet pkt;
    int status = 0;

    if(pt_pkt_sync_set(d, off) < 0)
        return 0;

    while(status >= 0) {
        status = pt_pkt_next(d, &pkt, sizeof(struct pt_packet));

        if(status < 0)
            break;


        if(pkt.type == ppt_psb) {
            uint64_t offset = 0;

            if(pt_pkt_get_offset(d, &offset) < 0)
                return 0;

            return offset;
        }
    }

    return 0;
}

static int setup_pt(struct pt_block_decoder** blk_dec, 
        struct pt_packet_decoder** pkt_dec, pt_file* trace)
{
    struct pt_config config;

    pt_config_init(&config);
    config.begin = (uint8_t*)trace->data;
    config.end = (uint8_t*)trace->data + trace->size;

    *blk_dec = pt_blk_alloc_decoder(&config);
    *pkt_dec = pt_pkt_alloc_decoder(&config);

    if(!blk_dec) {
        free(*blk_dec);
        return -1;
    }

    if(!pkt_dec) {
        free(*pkt_dec);
        return -1;
    }

    struct pt_image* image = pt_image_alloc(NULL);

    if(!image) {
        fprintf(stderr, "Could not allocate trace image\n");
        return -1;
    }
    
    for(pt_mapping* it = trace->maps; it != NULL; it = it->next) {
        int err = pt_image_add_file(image, it->filename, it->offset, it->size,
                NULL, it->start);

        if(err != 0 && strcmp(it->filename, "[vdso]") != 0)
            goto cleanup;
    }

    if(pt_blk_set_image(*blk_dec, image) < 0)
        goto cleanup;

    if(pt_blk_sync_forward(*blk_dec) < 0)
        goto cleanup;

    return 0;

cleanup:
    free(*pkt_dec);
    free(*blk_dec);
    free(image);

    return -1;
}

static void log_pt_err(struct pt_block_decoder* dec, enum pt_error_code err)
{
    // use pt_errstr
    uint64_t offset = 0;
    pt_blk_get_offset(dec, &offset);

    fprintf(stderr, "Critical error at offset 0x%lx -> %s\n", offset,
            pt_errstr(err));
}

static int do_trace_alt(char* exe_path, char* perf_path)
{
    int exit_status = 1;
    pt_file* ptfile = perf_data_parse(perf_path);

    if(!ptfile)
        goto nofree;

    mapped_page* mapped_pages = NULL;

    for(pt_mapping* it = ptfile->maps; it != NULL; it = it->next) {
        if(strcmp(exe_path, it->filename) == 0) {
            mapped_pages = mpp_add_section(mapped_pages, it->filename,
                    it->start, it->size, it->offset);
        }
    }

    if(!mapped_pages) {
        fprintf(stderr, "Could not find program mappings\n");
        goto ptfilefree;
    }

    struct pt_block_decoder* blk_dec;
    struct pt_packet_decoder* pkt_dec;

    if(setup_pt(&blk_dec, &pkt_dec, ptfile) < 0)
        goto ptfilefree;

    trace_writer stream;
    trace_writer_init(&stream);

    if(trace_writer_begin(&stream, "out.trace") < 0) {
        fprintf(stderr, "Error while opening output file\n");
        goto decoderfree;
    }

    int status = 0;
    uint64_t trace_offset = 0;
    ip_update next_jump = {0};
    struct pt_block block;

    next_jump.type = INS_INVALID;

    // TODO: Add function doing all the block querying to simplify the inner
    //       loop.

    while(status != -pte_eos) {
        status = pt_blk_next(blk_dec, &block, sizeof(struct pt_block));

        if(status == -pte_eos)
            break;

        pt_blk_get_offset(blk_dec, &trace_offset);

        if(status == -pte_nomap) {
            printf("Requested memory not mapped, skipping to next PSB\n");
            goto decoderfree;
        }

        if(status < 0) {
            log_pt_err(blk_dec, -status);
            goto decoderfree;
        }
    }

decoderfree:
    pt_image_free(pt_blk_get_image(blk_dec));
    pt_blk_free_decoder(blk_dec);
    pt_pkt_free_decoder(pkt_dec);
ptfilefree:
    free(ptfile);

nofree:
    return exit_status;
}

static int do_trace(char* full_path) {
    pt_file* ptfile = perf_data_parse(full_path);
    int exit_status = -1;

    if(!ptfile)
        goto nofree;

    pt_mapping* target = NULL;
    
    // We try to find our executable mappings
    for(pt_mapping* it = ptfile->maps; it != NULL; it = it->next) {
        if(strcmp("/bin/ls", it->filename) == 0)
            target = it;
    }

    if(!target) {
        fprintf(stderr, "Could not find mappings for file '%s'\n", full_path);
        pt_file_free(ptfile);
        return -1;
    }

    // Initializing trace mapping
    // This could be extended to libraries easily by adding
    // more entries into the traced_pages list
    traced_pages = mpp_add_section(NULL, target->filename, target->start,
            target->size, target->offset);

    if(traced_pages == NULL) {
        fprintf(stderr, "Could not map the traced_pages\n");
        pt_file_free(ptfile);
        return -1;
    }

    // Now let's start the processing part
    // First the image allocation part
    struct pt_image *image = pt_image_alloc(NULL);

    if(!image) {
        fprintf(stderr, "Could not allocate trace image\n");
        pt_image_free(image);
        return -1;
    }

    for(pt_mapping* it = ptfile->maps; it != NULL; it = it->next) {
        int err = pt_image_add_file(image, it->filename, it->offset, 
                it->size, NULL, it->start);

        if(err < 0) {
            if(strcmp(it->filename, "[vdso]") != 0) {
                fprintf(stderr, "Could not map %s\n", it->filename);
                pt_image_free(image);
                pt_file_free(ptfile);

                return -1;
            }
        }

        printf("0x%lx: %s (size = 0x%lx, offset = 0x%lx)\n",
                it->start, it->filename, it->size, it->offset);
    }

    // pt init
    struct pt_block_decoder *decoder;
    struct pt_packet_decoder *pkt_decoder;
    struct pt_config config;

    memset(&config, 0, sizeof(struct pt_config));
    config.size = sizeof(struct pt_config);
    config.begin = (uint8_t*)ptfile->data;
    config.end = (uint8_t*)ptfile->data + ptfile->size;

    decoder = pt_blk_alloc_decoder(&config);
    pkt_decoder = pt_pkt_alloc_decoder(&config);

    if(!decoder) {
        fprintf(stderr, "Error initializing pt library\n");
        pt_image_free(image);
        return -1;
    }
    
    pt_blk_set_image(decoder, image);
    pt_blk_sync_forward(decoder);

    // trace writer init
    trace_writer stream;
    trace_writer_init(&stream);

    if(trace_writer_begin(&stream, "out.trace") < 0) {
        perror("trace_writer");
        // TODO: free memory before exit
        return -1;
    }

    int status = 0;
    int emptyblock_count = 0;
    uint64_t trace_offset = 0;

    // Init tracing interface
    ip_update next_jump = {0};

    next_jump.type = INS_INVALID;

    for(;;) {
        struct pt_block block;

        status = pt_blk_next(decoder, &block, sizeof(struct pt_block));

        if(status == -pte_nomap) {
            printf("Warning: Requested memory not mapped, skipping to next PSB\n");
            status = pt_blk_sync_forward(decoder);
            continue;
        }

        // We reached the end of the stream
        if(status == -pte_eos)
            break;

        pt_blk_get_offset(decoder, &trace_offset);

        // Generic exit.
        if(status < 0 ) {
            fprintf(stderr, "Error %i while decoding packet at offset 0x%lx \n",
                    status, trace_offset);

            if(status == -pte_nomap)
                printf("nomap\n");

            if(status == -pte_internal)
                printf("internal error\n");

            fprintf(stderr, "Packet data: ");
            uint8_t* data = (uint8_t*)ptfile->data;

            for(int i = 0; i < 16; i++) {
                fprintf(stderr, "%02x ", data[trace_offset + i]);
            }

            fprintf(stderr, "\n");

            exit_status = -1;
            break;
        }

        // Now we see if any events are pending or if the end of the file is
        // reached.
        if(status & pts_event_pending) {
            struct pt_event evt;

            int evt_status = 0;

            // Skipping the events as they are useless for our purpose
            while(evt_status >= 0) {
                evt_status = pt_blk_event(decoder, &evt, 
                        sizeof(struct pt_event));
            }

        }

        if(status < 0) {
            fprintf(stderr, "Error while decoding (status %i)\n", status);
            exit_status = -1;
            break;
        }

        if(block.ninsn == 0) {
            emptyblock_count++;

            // On some executable there are a lot of empty blocks at the end
            // We can early return instead of being stuck in an infinite loop
            if(emptyblock_count > 100) {
                fprintf(stderr, "Warning: trace out of sync, skipping to next PSB\n");
                uint64_t off = pkt_next_psb(pkt_decoder, trace_offset);

                if(off == 0) {
                    printf("zero offset\n");
                    exit_status = -1;
                    break;
                }

                status = pt_blk_sync_forward(decoder);

                if(status == -pte_nosync) {
                    printf("bad\n");
                    return -1;
                }

                emptyblock_count = 0;
            }
        } else {
            if(mpp_inrange(traced_pages, block.ip)) {
                ip_update br = disasm_next_branch(disas, block.ip);

                if(next_jump.type == INS_INVALID) {
                    next_jump = br;
                } else if(next_jump.type == INS_JCC) {
                    if(block.ip == next_jump.target_ok) {
                        trace_writer_addedge(&stream, next_jump.address,
                                next_jump.target_ok);
                    } else if(block.ip == next_jump.target_fail) {
                        trace_writer_addedge(&stream, next_jump.address,
                                next_jump.target_fail);
                    }
                } else {
                    // If we have a call or a ret we reset the branch
                    // status
                    next_jump.type = INS_INVALID;
                }

                // We skip all direct branches until we read the next
                // conditional
                while(br.type == INS_JMP) {
                    trace_writer_addedge(&stream, br.address,
                            br.target_ok);
                    br = disasm_next_branch(disas, br.target_ok);
                }

                next_jump = br;
            }
        }
    }
    
    // Adding mappings
    for(mapped_page* it = traced_pages; it != NULL; it = it->next) {
        trace_writer_addmap(&stream, it->start, it->start + it->len);
    }

    trace_writer_save(&stream);

    mpp_free(traced_pages);
    pt_blk_free_decoder(decoder);
    pt_pkt_free_decoder(pkt_decoder);
    pt_image_free(image);

freeptfile:
    pt_file_free(ptfile);
nofree:

    return exit_status;
}

int do_pt_trace(char** argv, char** envp)
{
    if(access(argv[0], F_OK | R_OK) != 0) {
        fprintf(stderr, "Could not access file '%s'\n", argv[0]);
        return 1;
    }

    // Initializing the disassembler
    disas = disasm_new(read_pt);

    if(!disas) {
        fprintf(stderr, "Could not init capstone\n");
        return 1;
    }

    int trace_status = do_trace(argv[0]);

    disasm_free(disas);

    return trace_status;
}
