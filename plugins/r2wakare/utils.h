#ifndef UTILS_H
#define UTILS_H

#include <sqlite3.h>
#include <r_core.h>

typedef struct wkr_mapping_t {
    char* name;
    ut64 from;
    ut64 to;
} wkr_mapping;

typedef struct wkr_hitcount_t {
    ut64 address;
    ut64 count;
} wkr_hitcount;

typedef struct wkr_db_t {
    sqlite3* handle;
    bool pie;
    ut64 exec_off;
    ut64 map_low;
    ut64 map_high;
} wkr_db;

typedef enum wkr_err_t {
    WKR_OK,
    WKR_FORMAT,
    WKR_PROG,
    WKR_SQLITE
} wkr_err;

wkr_err wkr_db_open(wkr_db* db, RCore* core, const char* filename);
wkr_err wkr_db_close(wkr_db* db);
const char* wkr_db_errmsg(wkr_db* db, wkr_err err);
wkr_err wkr_db_branchcount(wkr_db* db, int* count);
wkr_err wkr_db_mapcount(wkr_db* db, int* count);
wkr_err wkr_db_hitcount(wkr_db* db, int* count);
wkr_err wkr_db_mappings(wkr_db* db, RList** res); // RList<wkr_mapping>
wkr_err wkr_db_bbs(wkr_db* db, RList** res); // RList<wkr_hitcount>
wkr_err wkr_db_xrefs(wkr_db* db, ut64 address, RList** res); // RList<wkr_hitcount>
ut64 wkr_db_frompie(wkr_db* db, ut64 address);
ut64 wkr_db_topie(wkr_db* db, ut64 address);

#endif
