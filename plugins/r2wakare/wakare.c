#include <string.h>
#include <r_core.h>
#include <sqlite3.h>
#include "utils.h"

wkr_db tracedb;
RList* bb_list = NULL;

static const char* usage[] = {
    "Wakare plugin:",
    "\\wkro [file]  : Open a trace database",
    "\\wkri         : Displays information about the loaded database",
    "\\wkrx         : Displays the xrefs from the current address",
    "\\wkrbl        : Displays the list of basic blocks",
    "\\wkrbh        : Adds hitcounts in basic blocks comments",
    "\\wkrbc        : Cleans the hitcount comments",
    "\\wkrdd [file] : Does a difference based diffing with another trace",
    "\\wkrdi [file] : Does an intersection based diffing with another trace",
    "\\wkrdr        : Resets the database to its original state",
    NULL
};

static void print_usage()
{
    for(int i = 0; usage[i] != NULL; i++)
        r_cons_printf("%s\n", usage[i]);
}

// wkro: Opens a trace database
static void cmd_wkro(RCore* core, const char* filename)
{
    wkr_err err = wkr_db_open(&tracedb, core, filename);

    if(err != WKR_OK) {
        wkr_db_close(&tracedb);
        r_cons_printf("Error while opening database: %s\n", wkr_db_errmsg(&tracedb, err));
        return;
    }

    if((err = wkr_db_bbs(&tracedb, &bb_list)) != WKR_OK) {
        bb_list = NULL;
        wkr_db_close(&tracedb);
        r_cons_printf("Error while gettings basic blocks: %s\n", wkr_db_errmsg(&tracedb ,err));
        return;
    }
}

// wkri: Displays information about the currently loaded trace database
static void cmd_wkri()
{
    if(tracedb.handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    int hitcount = 0;
    int branchcount = 0;
    int mapcount = 0;
    wkr_err err;

    if((err = wkr_db_hitcount(&tracedb, &hitcount)) != WKR_OK)
        goto fail;

    if((err = wkr_db_branchcount(&tracedb, &branchcount)) != WKR_OK)
        goto fail;

    if((err = wkr_db_mapcount(&tracedb, &mapcount)) != WKR_OK)
        goto fail;

    RList* mappings = NULL;

    if((err = wkr_db_mappings(&tracedb, &mappings)) != WKR_OK)
        goto fail;

    r_cons_printf("Branches     : %i\n", branchcount);
    r_cons_printf("Basic blocks : %i\n", hitcount);
    r_cons_printf("Mappings     : %i\n", mapcount);
    r_cons_printf("----- Mapping list -----\n");

    RListIter* iter;
    wkr_mapping* map;

    r_list_foreach(mappings, iter, map) {
        r_cons_printf("0x%lx - 0x%lx:  %s\n",
                map->from, map->to, map->name);
    }

    r_list_free(mappings);

    return;

fail:
    r_cons_printf("Error while getting trace info: %s\n", wkr_db_errmsg(&tracedb, err));
}

// wkrx: Displays branch xrefs from the current address
static void cmd_wkrx(RCore* core)
{
    if(tracedb.handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    wkr_err err;
    RList* xref_list;
    RListIter* iter;
    wkr_hitcount* it_hitcount;

    if((err = wkr_db_xrefs(&tracedb, core->offset, &xref_list)) != WKR_OK) {
        r_cons_printf("Error while gettings xrefs: %s\n", wkr_db_errmsg(&tracedb, err));
        return;
    }

    // Printing the result
    r_cons_printf("--- Found %i xrefs from 0x%lx ---\n",
            r_list_length(xref_list), core->offset);

    r_list_foreach(xref_list, iter, it_hitcount) {
        r_cons_printf("0x%lx: %u\n", it_hitcount->address, it_hitcount->count);
    }

    r_list_free(xref_list);
}

// wkrbb: Displays the list of basic blocks
static void cmd_wkrbl()
{
    if(bb_list == NULL || tracedb.handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    RListIter* iter;
    wkr_hitcount* hit;

    // TODO: Add function name resolution
    r_list_foreach(bb_list, iter, hit) {
        r_cons_printf("0x%lx: %lu\n", wkr_db_frompie(&tracedb, hit->address), hit->count);
    }
}

// wkrbh: Adds comments to basic blocks specifying their hitcount
static void cmd_wkrbh(RCore* core)
{
    if(tracedb.handle == NULL || bb_list == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    RListIter* iter;
    wkr_hitcount* hit;

    // TODO: Handle overlapping comments
    r_list_foreach(bb_list, iter, hit) {
        char* cmt = r_str_newf("(hitcount: %d)", hit->count);
        r_meta_set_string(core->anal, R_META_TYPE_COMMENT,
                wkr_db_frompie(&tracedb, hit->address), cmt);
        free(cmt);
    }
}

// wkrbc: Clears wakare comments on top of basic blocks (deletes first comment
// of basic blocks)
static void cmd_wkrbc(RCore* core)
{
    if(tracedb.handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    wkr_err err;
    RList* bbs = NULL;

    if((err = wkr_db_bbs(&tracedb, &bbs)) != WKR_OK) {
        r_cons_printf("Could not get basic blocks: %s\n", wkr_db_errmsg(&tracedb, err));
        return;
    }

    RListIter* iter;
    wkr_hitcount* hit;

    // TODO: Handle overlapping comments
    r_list_foreach(bbs, iter, hit) {
        r_meta_del(core->anal, R_META_TYPE_COMMENT,
                wkr_db_frompie(&tracedb, hit->address), 1);
    }

    r_list_free(bbs);
}

// wkrdr: Resets the cached basic block list to its original state
static void cmd_wkrdr()
{
    if(tracedb.handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    r_list_free(bb_list);
    bb_list = NULL;
    wkr_err err;

    if((err = wkr_db_bbs(&tracedb, &bb_list)) != WKR_OK) {
        r_cons_printf("Could not get basic blocks: %s\n", wkr_db_errmsg(&tracedb, err));
    }
}

static int cmd_handler(void* user, const char* input)
{
    RCore* core = (RCore*)user;

    if(r_str_cmp(input, "\\wkr", 4) != 0 || r_str_ansi_len(input) < 4) {
        return 0;
    }

    switch(input[4]) {
        case 'o':
            cmd_wkro(core, r_str_trim_ro(input + 5));
            break;
        case 'i':
            cmd_wkri();
            break;
        case 'x':
            cmd_wkrx(core);
            break;
        case 'd':
            switch(input[5]) {
                case 'd':
                    r_cons_printf("difference diffing\n");
                    break;
                case 'i':
                    r_cons_printf("intersection diffing\n");
                    break;
                case 'r':
                    cmd_wkrdr();
                    break;
                default:
                    print_usage();
                    break;
            }
            break;
        case 'b':
            switch(input[5]) {
                case 'l':
                    cmd_wkrbl();
                    break;
                case 'h':
                    cmd_wkrbh(core);
                    break;
                case 'c':
                    cmd_wkrbc(core);
                    break;
                default:
                    print_usage();
                    break;
            }
            break;
        default:
            print_usage();
    }

    return 0;
}

RCorePlugin r_core_plugin_wakare = {
    .name = "wakare",
    .author = "Sideway",
    .desc = "Loads execution traces from sqlite databases generated by Wakare",
    .call = cmd_handler,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_CORE,
    .data = &r_core_plugin_wakare,
    .version = R2_VERSION
};
#endif
