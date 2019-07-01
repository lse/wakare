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

static int setup_pt(struct pt_block_decoder** blk_dec, pt_file* trace)
{
    struct pt_config config;

    pt_config_init(&config);
    config.begin = (uint8_t*)trace->data;
    config.end = (uint8_t*)trace->data + trace->size;

    *blk_dec = pt_blk_alloc_decoder(&config);

    if(!blk_dec) {
        free(*blk_dec);
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

static int do_trace(char* perf_path, char* exe_path)
{
    int exit_status = 1;
    pt_file* ptfile = perf_data_parse(perf_path);

    if(!ptfile)
        goto nofree;

    traced_pages = NULL;

    for(pt_mapping* it = ptfile->maps; it != NULL; it = it->next) {
        if(strcmp(exe_path, it->filename) == 0) {
            traced_pages = mpp_add_section(traced_pages, it->filename,
                    it->start, it->size, it->offset);
        }
    }

    if(!traced_pages) {
        fprintf(stderr, "Could not find program mappings\n");
        goto ptfilefree;
    }

    struct pt_block_decoder* blk_dec;

    if(setup_pt(&blk_dec, ptfile) < 0)
        goto ptfilefree;

    trace_writer stream;
    trace_writer_init(&stream);

    if(trace_writer_begin(&stream, "out.trace") < 0) {
        fprintf(stderr, "Error while opening output file\n");
        goto decoderfree;
    }

    int status = 0;
    ip_update next_jump = {0};
    struct pt_block block;
    int emptycount = 0;

    next_jump.type = INS_INVALID;

    while(status != -pte_eos) {
        status = pt_blk_next(blk_dec, &block, sizeof(struct pt_block));

        if(status == -pte_eos) {
            break;
        } else if(status == -pte_nosync || status == -pte_nomap || emptycount > 100) {
            fprintf(stderr, "Warning: Trace out of sync, skipping to next PSB\n");
            status = pt_blk_sync_forward(blk_dec);
            emptycount = 0;

            if(status == -pte_eos) {
                fprintf(stderr, "No new PSB\n");
                break;
            }

            if(status < 0) {
                log_pt_err(blk_dec, -status);
                goto decoderfree;
            }

            continue;
        } else if(status < 0) {
            log_pt_err(blk_dec, -status);
            goto decoderfree;
        }

        // If there are events we skip them as otherwise we can't query the
        // next block.
        if(status & pts_event_pending) {
            struct pt_event evt;
            int evt_status = 0;

            while(evt_status >= 0) {
                evt_status = pt_blk_event(blk_dec, &evt,
                        sizeof(struct pt_event));
            }
        }

        if(block.ninsn == 0) {
            emptycount++;
            continue;
        }

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

    exit_status = 0;

    for(mapped_page* it = traced_pages; it != NULL; it = it->next) {
        trace_writer_addmap(&stream, it->start, it->start + it->len);
    }

    trace_writer_save(&stream);

decoderfree:
    pt_image_free(pt_blk_get_image(blk_dec));
    pt_blk_free_decoder(blk_dec);
maps_free:
    mpp_free(traced_pages);
ptfilefree:
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

    char* binary_path = realpath(argv[1], NULL);

    if(binary_path == NULL) {
        fprintf(stderr, "Could not resolve path to '%s'\n", argv[1]);
        disasm_free(disas);
        return 1;
    }

    if(access(binary_path, F_OK) != 0) {
        fprintf(stderr, "File '%s' does not exist\n", binary_path);
        free(binary_path);
        disasm_free(disas);
        return 1;
    }

    int trace_status = do_trace(argv[0], binary_path);

    disasm_free(disas);
    free(binary_path);

    return trace_status;
}
