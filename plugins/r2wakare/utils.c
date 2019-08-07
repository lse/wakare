#include <string.h>
#include <r_core.h>
#include "utils.h"

static void wkr_mapping_free(void* obj)
{
    wkr_mapping* wobj = (wkr_mapping*)obj;
    free(wobj->name);
    free(wobj);
}

static wkr_err sql_count_rows(sqlite3* handle, const char* column_name, int* count)
{
    sqlite3_stmt* query = NULL;
    char* buff = r_str_newf("SELECT COUNT(*) FROM %s;", column_name);

    if(sqlite3_prepare_v2(handle, buff, -1, &query, 0) != SQLITE_OK) {
        free(buff);
        return WKR_SQLITE;
    }

    if(sqlite3_step(query) != SQLITE_ROW) {
        free(buff);
        sqlite3_finalize(query);
        return WKR_SQLITE;
    }

    *count = sqlite3_column_int(query, 0);
    sqlite3_finalize(query);
    free(buff);

    return WKR_OK;
}

wkr_err wkr_db_open(wkr_db* db, RCore* core, const char* filename)
{
    memset(db, 0, sizeof(wkr_db));

    // Opening the db
    if(sqlite3_open_v2(filename, &db->handle, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        return WKR_SQLITE;
    }

    int count = 0;

    // Sanity checking (making sure the required sections are present)
    if(sql_count_rows(db->handle, "branches", &count) != WKR_OK ||
            sql_count_rows(db->handle, "hitcounts", &count) != WKR_OK ||
            sql_count_rows(db->handle, "mappings", &count) != WKR_OK) {
        return WKR_FORMAT;
    }

    // Checking if the executable is in the trace
    wkr_err err;
    bool is_present = false;
    RList* mappings = NULL;
    RListIter* it = NULL;
    wkr_mapping* map = NULL;
    const char* file_basename = r_file_basename(core->bin->file);

    if((err = wkr_db_mappings(db, &mappings)) != WKR_OK) {
        return err;
    }

    r_list_foreach(mappings, it, map) {
        if(r_str_endswith(map->name, file_basename)) {
            is_present = true;
            db->map_low = map->from;
            db->map_high = map->to;
        }
    }

    r_list_free(mappings);

    if(!is_present) {
        return WKR_PROG;
    }

    // Now checking for PIE (setting up address translation)
    db->pie = r_bin_get_baddr(core->bin) == 0;

    if(db->pie) {
        RBinSection* section;

        r_list_foreach(r_bin_get_sections(core->bin), it, section) {
            if(section->is_segment && section->perm & R_PERM_X) {
                db->exec_off = section->paddr;
                break;
            }
        }

        if(db->exec_off == 0) {
            return WKR_FORMAT;
        }
    }

    return WKR_OK;
}

wkr_err wkr_db_close(wkr_db* db)
{
    sqlite3_close(db->handle);
    db->handle = NULL;
}

const char* wkr_db_errmsg(wkr_db* db, wkr_err err)
{
    switch(err) {
        case WKR_OK:
            return "No error";
        case WKR_SQLITE:
            return sqlite3_errmsg(db->handle);
        case WKR_FORMAT:
            return "Database is not a valid wakare trace";
        case WKR_PROG:
            return "Trace does not contain the specified executable";
        default:
            return "Unknown error";
    }
}

wkr_err wkr_db_branchcount(wkr_db* db, int* count)
{
    return sql_count_rows(db->handle, "branches", count);
}

wkr_err wkr_db_mapcount(wkr_db* db, int* count)
{
    return sql_count_rows(db->handle, "mappings", count);
}

wkr_err wkr_db_hitcount(wkr_db* db, int* count)
{
    return sql_count_rows(db->handle, "hitcounts", count);
}

// RList<wkr_mapping>
wkr_err wkr_db_mappings(wkr_db* db, RList** res)
{
    sqlite3_stmt* query = NULL;
    if(sqlite3_prepare_v2(db->handle, "SELECT * FROM mappings;", -1, &query, 0) != SQLITE_OK) {
        return WKR_SQLITE;
    }

    int err = 0;
    RList* mapping_list = r_list_newf(wkr_mapping_free);

    while((err = sqlite3_step(query)) != SQLITE_DONE) {
        if(err != SQLITE_ROW) {
            r_list_free(mapping_list);
            return WKR_SQLITE;
        }

        wkr_mapping* map = R_NEW0(wkr_mapping);
        map->name = strdup(sqlite3_column_text(query, 1));
        map->from = sqlite3_column_int64(query, 2);
        map->to = sqlite3_column_int64(query, 3);

        r_list_append(mapping_list, map);
    }

    sqlite3_finalize(query);
    *res = mapping_list;

    return WKR_OK;
}

wkr_err wkr_db_bbs(wkr_db* db, RList** res)
{
    sqlite3_stmt* query = NULL;

    if(sqlite3_prepare_v2(db->handle, "SELECT * FROM hitcounts;", -1, &query, 0) != SQLITE_OK) {
        return WKR_SQLITE;
    }

    int err = 0;
    RList* hitcount_list = r_list_new();

    while((err = sqlite3_step(query)) != SQLITE_DONE) {
        if(err != SQLITE_ROW) {
            r_list_free(hitcount_list);
            return WKR_SQLITE;
        }

        wkr_hitcount* hit = R_NEW0(wkr_hitcount);
        hit->address = wkr_db_frompie(db, sqlite3_column_int64(query, 1));
        hit->count = sqlite3_column_int64(query, 2);

        r_list_append(hitcount_list, hit);
    }

    sqlite3_finalize(query);
    *res = hitcount_list;

    return WKR_OK;
}

wkr_err wkr_db_xrefs(wkr_db* db, ut64 address, RList** res)
{
    sqlite3_stmt* query = NULL;

    if(sqlite3_prepare_v2(db->handle, "SELECT * FROM branches WHERE source=?1;",
                -1, &query, 0) != SQLITE_OK) {
        return WKR_SQLITE;
    }

    if(sqlite3_bind_int64(query, 1, wkr_db_topie(db, address)) != SQLITE_OK) {
        return WKR_SQLITE;
    }

    int err = 0;
    RList* xref_list = r_list_new();
    RListIter* iter;

    while((err = sqlite3_step(query)) != SQLITE_DONE) {
        if(err != SQLITE_ROW) {
            r_list_free(xref_list);
            sqlite3_finalize(query);
            return WKR_SQLITE;
        }

        ut64 destination = wkr_db_frompie(db, sqlite3_column_int64(query, 3));
        wkr_hitcount* hit = NULL;
        wkr_hitcount* it = NULL;

        r_list_foreach(xref_list, iter, it) {
            if(it->address == destination) {
                hit = it;
                break;
            }
        }

        if(hit) {
            hit->count++;
        } else {
            hit = R_NEW0(wkr_hitcount);
            hit->address = destination;
            hit->count = 1;
            r_list_append(xref_list, hit);
        }
    }

    *res = xref_list;

    return WKR_OK;
}

ut64 wkr_db_frompie(wkr_db* db, ut64 address)
{
    if(db->pie) {
        // Should not happen
        if(address < db->map_low || address > db->map_high)
            return address;

        return (address - db->map_low) + db->exec_off;
    }

    return address;
}

ut64 wkr_db_topie(wkr_db* db, ut64 address)
{
    if(db->pie) {
        return (address - db->exec_off) + db->map_low;
    }

    return address;
}
