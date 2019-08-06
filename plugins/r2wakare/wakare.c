#include <string.h>
#include <r_core.h>
#include <sqlite3.h>

static sqlite3* tracedb_handle = NULL;
static RList* bb_list = NULL;

// Dictates whether address translation will take place
static bool is_pie = false;

static ut64 exec_off = 0; // Offset to segment within the binary
static ut64 map_low = 0;  // Lower bound of the segment within the trace
static ut64 map_high = 0; // Upper bound of the segment within the trace

// Wakare defined types
typedef struct wkr_mapping_t {
    char* name;
    ut64 from;
    ut64 to;
} wkr_mapping;

typedef struct wkr_hitcount_t {
    ut64 address;
    ut64 count;
} wkr_hitcount;

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

static void wkr_mapping_free(void* obj)
{
    wkr_mapping* wobj = (wkr_mapping*)obj;
    free(wobj->name);
    free(wobj);
}

// Returns a RList<wkr_mapping> in success, NULL on error
static RList* get_mappings(sqlite3* handle)
{
    sqlite3_stmt* query = NULL;
    RList* mapping_list = NULL;

    if(sqlite3_prepare_v2(handle, "SELECT * FROM mappings;", -1, &query, 0) != SQLITE_OK) {
        r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(handle));
        return NULL;
    }

    int err = 0;
    mapping_list = r_list_newf(wkr_mapping_free);

    while((err = sqlite3_step(query)) != SQLITE_DONE) {
        if(err != SQLITE_ROW) {
            r_list_free(mapping_list);
            r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(handle));
            return NULL;
        }

        wkr_mapping* map = R_NEW0(wkr_mapping);
        map->name = strdup(sqlite3_column_text(query, 1));
        map->from = sqlite3_column_int64(query, 2);
        map->to = sqlite3_column_int64(query, 3);

        r_list_append(mapping_list, map);
    }

    sqlite3_finalize(query);

    return mapping_list;
}

// Returns a RList<wkr_hitcount> on success, NULL on error
static RList* get_hitcounts(sqlite3* handle)
{
    sqlite3_stmt* query = NULL;
    RList* hitcount_list = NULL;

    if(sqlite3_prepare_v2(handle, "SELECT * FROM hitcounts ORDER BY hitcount DESC;", -1, &query, 0) != SQLITE_OK) {
        r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(handle));
        return NULL;
    }

    int err = 0;
    hitcount_list = r_list_new();

    while((err = sqlite3_step(query)) != SQLITE_DONE) {
        if(err != SQLITE_ROW) {
            r_list_free(hitcount_list);
            r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(handle));
            return NULL;
        }

        wkr_hitcount* hit = R_NEW0(wkr_hitcount);
        hit->address = sqlite3_column_int64(query, 1);
        hit->count = sqlite3_column_int64(query, 2);

        r_list_append(hitcount_list, hit);
    }

    sqlite3_finalize(query);

    return hitcount_list;
}

static int sql_count_rows(sqlite3* handle, const char* column_name)
{
    sqlite3_stmt* query = NULL;
    char buff[256] = {0};
    snprintf(buff, sizeof(buff), "SELECT COUNT(*) FROM %s;", column_name);

    if(sqlite3_prepare_v2(handle, buff, -1, &query, 0) != SQLITE_OK) {
        r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(handle));
        return -1;
    }

    if(sqlite3_step(query) != SQLITE_ROW) {
        r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(handle));
        sqlite3_finalize(query);
        return -1;
    }

    int count = sqlite3_column_int(query, 0);
    sqlite3_finalize(query);

    return count;
}

static ut64 pie_to_phys(ut64 address)
{
    if(is_pie) {
        // Should not happen
        if(address < map_low || address > map_high)
            return address;

        return (address - map_low) + exec_off;
    }

    return address;
}

static ut64 phys_to_pie(ut64 address)
{
    if(is_pie)
        return (address - exec_off) + map_low;

    return address;
}

// wkro: Opens a trace database
static void cmd_wkro(RCore* core, const char* filename)
{
    sqlite3* handle = NULL;
    RListIter* iter = NULL;

    if(sqlite3_open_v2(filename, &handle, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(handle));
        return;
    }

    // We need to do some sanity checking
    int branches_count = sql_count_rows(handle, "branches");
    int hitcounts_count = sql_count_rows(handle, "hitcounts");
    int mappings_count = sql_count_rows(handle, "mappings");

    if(branches_count < 0 || hitcounts_count < 0 || mappings_count < 0) {
        r_cons_printf("Database is not a valid wakare trace\n");
        goto cleanup;
    }

    // Checking if the executable is in the trace
    bool is_present = false;
    wkr_mapping* mapping;
    RList* mappings = get_mappings(handle);
    const char* file_basename = r_file_basename(core->bin->file);

    r_list_foreach(get_mappings(handle), iter, mapping) {
        if(r_str_endswith(mapping->name, file_basename)) {
            is_present = true;
            map_low = mapping->from;
            map_high = mapping->to;
        }
    }

    r_list_free(mappings);

    if(!is_present) {
        r_cons_printf("Could not current file in trace mappings\n");
        goto cleanup;
    }

    // Now checking for PIE (setting up address translation)
    is_pie = r_bin_get_baddr(core->bin) == 0;

    // If the executable is PIE we need to get the offset of the segment to
    // be able to do the conversion between trace addresses and real/physical
    // addresses.
    if(is_pie) {
        RBinSection* section;

        r_list_foreach(r_bin_get_sections(core->bin), iter, section) {
            if(section->is_segment) {
                // As we only get the first executable segment for now this
                // approach will not work on files with multiple executable
                // segments.
                if(section->perm & R_PERM_X) {
                    // vaddr == paddr for PIE
                    exec_off = section->paddr;
                    break;
                }
            }
        }

        if(exec_off == 0) {
            r_cons_printf("Could not find executable segment\n");
            goto cleanup;
        }
    }

    // Finally getting the hitcounts
    bb_list = get_hitcounts(handle);

    if(bb_list == NULL) {
        r_cons_printf("Could not get basic block hits\n");
        goto cleanup;
    }

    tracedb_handle = handle;
    r_cons_printf("Trace database successfully loaded\n");

    return;

cleanup:
    sqlite3_close(handle);
}

// wkri: Displays information about the currently loaded trace database
static void cmd_wkri()
{
    if(tracedb_handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    int branches_count = sql_count_rows(tracedb_handle, "branches");
    int hitcounts_count = sql_count_rows(tracedb_handle, "hitcounts");
    int mappings_count = sql_count_rows(tracedb_handle, "mappings");

    RList* mappings = get_mappings(tracedb_handle);

    r_cons_printf("Branches     : %i\n", branches_count);
    r_cons_printf("Basic blocks : %i\n", hitcounts_count);
    r_cons_printf("Mappings     : %i\n", mappings_count);
    r_cons_printf("----- Mapping list -----\n");

    RListIter* iter;
    wkr_mapping* map;

    r_list_foreach(mappings, iter, map) {
        r_cons_printf("0x%lx - 0x%lx:  %s\n",
                map->from, map->to, map->name);
    }
}

// wkrx: Displays branch xrefs from the current address
static void cmd_wkrx(RCore* core)
{
    if(tracedb_handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    sqlite3_stmt* query = NULL;

    if(sqlite3_prepare_v2(tracedb_handle, "SELECT * FROM branches WHERE source=?1;",
                -1, &query, 0) != SQLITE_OK) {
        r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(tracedb_handle));
        return;
    }

    if(sqlite3_bind_int64(query, 1, phys_to_pie(core->offset)) != SQLITE_OK) {
        r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(tracedb_handle));
        return;
    }

    int err = 0;
    RList* xref_list = r_list_new();
    RListIter* iter;
    wkr_hitcount* it_hitcount;

    while((err = sqlite3_step(query)) != SQLITE_DONE) {
        if(err != SQLITE_ROW) {
            r_cons_printf("sqlite3: %s\n", sqlite3_errmsg(tracedb_handle));
            break;
        }

        ut64 target = pie_to_phys(sqlite3_column_int64(query, 3));
        wkr_hitcount* hit = NULL;

        r_list_foreach(xref_list, iter, it_hitcount) {
            if(it_hitcount->address == target) {
                hit = it_hitcount;
                break;
            }
        }

        if(hit) {
            hit->count++;
        } else {
            hit = R_NEW0(wkr_hitcount);
            hit->address = target;
            hit->count = 1;
            r_list_append(xref_list, hit);
        }
    }

    sqlite3_finalize(query);

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
    if(bb_list == NULL || tracedb_handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    RListIter* iter;
    wkr_hitcount* hit;

    // TODO: Add function name resolution
    r_list_foreach(bb_list, iter, hit) {
        r_cons_printf("0x%lx: %lu\n", pie_to_phys(hit->address), hit->count);
    }
}

// wkrbh: Adds comments to basic blocks specifying their hitcount
static void cmd_wkrbh(RCore* core)
{
    if(tracedb_handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    RList* bbs = get_hitcounts(tracedb_handle);

    if(bbs == NULL)
        return;

    RListIter* iter;
    wkr_hitcount* hit;

    // TODO: Handle overlapping comments
    r_list_foreach(bbs, iter, hit) {
        char* cmt = r_str_newf("(hitcount: %d)", hit->count);
        r_meta_set_string(core->anal, R_META_TYPE_COMMENT,
                pie_to_phys(hit->address), cmt);
        free(cmt);
    }

    r_list_free(bbs);
}

static void cmd_wkrbc(RCore* core)
{
    if(tracedb_handle == NULL) {
        r_cons_printf("No database was loaded\n");
        return;
    }

    RList* bbs = get_hitcounts(tracedb_handle);

    if(bbs == NULL)
        return;

    RListIter* iter;
    wkr_hitcount* hit;

    // TODO: Handle overlapping comments
    r_list_foreach(bbs, iter, hit) {
        r_meta_del(core->anal, R_META_TYPE_COMMENT,
                pie_to_phys(hit->address), 1);
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
                    r_cons_printf("reset diffing\n");
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
