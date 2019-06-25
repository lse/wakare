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

    if(mem == NULL)
        return NULL;

    close(fd);

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

static int do_trace(char* full_path) {
    pt_file* ptfile = perf_data_parse(PT_TEMP_FILE);

    if(!ptfile)
        return -1;

    if(ptfile->size == -1 || ptfile->data == NULL) {
        fprintf(stderr, "File didn't contain pt data\n");
        pt_file_free(ptfile);
        return -1;
    }

    pt_mapping* target = NULL;
    
    // We try to find our executable mappings
    for(pt_mapping* it = ptfile->maps; it != NULL; it = it->next) {
        if(strcmp(full_path, it->filename) == 0)
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
    struct pt_config config;

    memset(&config, 0, sizeof(struct pt_config));
    config.size = sizeof(struct pt_config);
    config.begin = (uint8_t*)ptfile->data;
    config.end = (uint8_t*)ptfile->data + ptfile->size;

    decoder = pt_blk_alloc_decoder(&config);

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

    int exit_status = 0;
    int status = 0;
    int emptyblock_count = 0;

    // Init tracing interface
    ip_update next_jump = {0};

    next_jump.type = INS_INVALID;

    for(;;) {
        struct pt_block block;

        status = pt_blk_next(decoder, &block, sizeof(struct pt_block));

        // We reached the end of the stream
        if(status == -pte_eos)
            break;

        // Generic exit.
        if(status < 0 ) {
            uint64_t offset = 0;
            pt_blk_get_offset(decoder, &offset);

            fprintf(stderr, "Error %i while decoding packet at offset 0x%lx \n",
                    status, offset);
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
                fprintf(stderr, "Warning: encountered too many empty blocks\n");
                break;
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
    pt_image_free(image);
    pt_file_free(ptfile);

    return exit_status;
}

int do_pt_trace(char** argv, char** envp)
{
    // Check if pt is supported (/sys/devices/intel_pt)
    if(access("/sys/devices/intel_pt", F_OK) != 0) {
        fprintf(stderr, "This device does not support intel_pt\n");
        return -1;
    }

    // Check if perf is installed
    if(access("/usr/bin/perf", F_OK) != 0) {
        fprintf(stderr, "Please install perf at /usr/bin/perf\n");
        return -1;
    }

    // Check if the executable is available
    if(access(argv[0], F_OK) != 0) {
        fprintf(stderr, "Could not find executable '%s'\n", argv[0]);
        return -1;
    }

    char* full_path = malloc(PATH_MAX);

    if(!realpath(argv[0], full_path)) {
        fprintf(stderr, "Could not get full path of '%s'\n", argv[0]);
        free(full_path);
        return -1;
    }

    // Initializing the disassembler
    disas = disasm_new(read_pt);

    if(!disas) {
        fprintf(stderr, "Could not init capstone\n");
        return -1;
    }
    
    // We disable timing information (tsc, mtc) because we don't need it
    // and we also disable return compression (noretcomp) to get a trace 
    // that is easier to process (no need to keep a virtual return stack)
    char* perf_cmd[] = {
        "/usr/bin/perf", "record", "-e", 
        "intel_pt/tsc=0,mtc=0,noretcomp=1/u",
        "-o", PT_TEMP_FILE
    };
    
    int perf_cmd_len = sizeof(perf_cmd) / sizeof(char*);
    int usr_cmd_len = 0;

    for(int i = 0; argv[i] != NULL; i++)
        usr_cmd_len++;

    int final_cmd_len = (usr_cmd_len + 1 + perf_cmd_len);
    char** combined_argv = malloc(sizeof(char*) * final_cmd_len);
    
    // Combining argvs
    for(int i = 0; i < (final_cmd_len - 1); i++) {
        if(i < perf_cmd_len) {
            combined_argv[i] = perf_cmd[i];
        } else {
            combined_argv[i] = argv[i - perf_cmd_len];
        }
    }

    combined_argv[final_cmd_len - 1] = 0;

    // Now executing perf command
    pid_t child = fork();

    if(child == -1) {
        fprintf(stderr, "Fork failed\n");
        free(full_path);
        return -1;
    }

    if(child == 0) {
        execve(combined_argv[0], combined_argv, envp);
        fprintf(stderr, "There was an error executing perf\n");
        perror("execve");
        exit(-1);
    }
    
    // Now waiting for process to finish
    int status = 0;

    while(1) {
        pid_t id = waitpid(child, &status, 0);

        if(id < 0) {
            fprintf(stderr, "watipid() failed\n");
            perror("waitpid");

            free(full_path);
            return -1;
        }
        
        if(WIFEXITED(status) || WIFSIGNALED(status) ) {
            break;
        }
    }

    int trace_status = do_trace(full_path);

    free(full_path);
    free(combined_argv);
    disasm_free(disas);

    return trace_status;
}
