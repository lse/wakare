#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "tracer/utils.h"

static int parse_map_line(char* line, mempage* result)
{
    char buff[5];
    int cnt = sscanf(line, "%lx-%lx %4s", &result->start, &result->end, buff);

    if(cnt != 3)
        return 0;

    result->perms = 0;
    result->perms |= (buff[0] == 'r') ? PERM_R : 0;
    result->perms |= (buff[1] == 'w') ? PERM_W : 0;
    result->perms |= (buff[2] == 'x') ? PERM_X : 0;

    return 1;
}

mempage* mempages_get(pid_t target)
{
    char buff[256] = {0};
    char prog_path[256] = {0};
    
    snprintf(buff, sizeof(buff)-1, "/proc/%d/maps", target);
    FILE* fp = fopen(buff, "r");

    if(fp == NULL) {
        fprintf(stderr, "Could not open %s\n", buff);
        return NULL;
    }

    // Now we get the executable path from /proc/[pid]/exe
    snprintf(buff, sizeof(buff)-1, "/proc/%d/exe", target);

    if(readlink(buff, prog_path, sizeof(prog_path)-1) < 0) {
        fprintf(stderr, "Could not find executable path\n");
        fclose(fp);

        return NULL;
    }

    mempage* page_list = NULL;
    mempage* page_head = NULL;

    // If everything is fine we extract the mappings
    while(fgets(buff, sizeof(buff), fp) != NULL) {
        if(strstr(buff, prog_path) != NULL) {
            mempage* cur = malloc(sizeof(mempage));
            cur->next = NULL;

            // Parse line
            if(!parse_map_line(buff, cur)) {
                fprintf(stderr, "Error while parsing mapping, skipping...\n");
                free(cur);
            } else {
                if(page_list) {
                    page_head->next = cur;
                    page_head = cur;
                } else {
                    page_list = cur;
                    page_head = cur;
                }
            }
        }
    }

    fclose(fp);

    return page_list;
}

int align_pagesize(int size)
{
    int ps = getpagesize();
    return (size + ps) & (~(ps - 1));
}

// bytestream
bytestream* bytestream_new(size_t capacity)
{
    bytestream* bs = malloc(sizeof(bytestream));
    bs->capacity = capacity;
    bs->len = 0;
    bs->data = malloc(sizeof(capacity));

    return bs;
}

void bytestream_write(bytestream* bs, void* data, size_t size)
{
    if(bs->len + size > bs->capacity) {
        bs->capacity = 2 * (bs->capacity + size);
        bs->data = realloc(bs->data, bs->capacity);
    }

    char* dst = ((char*)bs->data) + bs->len;

    memcpy(dst, data, size);
    bs->len += size;
}

void bytestream_free(bytestream* bs)
{
    free(bs->data);
    free(bs);
}
