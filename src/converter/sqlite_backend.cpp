#include <string>
#include <cstdint>
#include <sqlite3.h>
#include "converter/sqlite_backend.hh"

void SqliteBackend::check_flush()
{
    if(stmt_tr_count_ == 0)
        sqlite3_exec(sqlite_handle_, "BEGIN TRANSACTION;", 0, 0, 0);

    if(stmt_tr_count_ >= COMMIT_THRESHOLD) {
        sqlite3_exec(sqlite_handle_, "END TRANSACTION;", 0, 0, 0);
        sqlite3_exec(sqlite_handle_, "BEGIN TRANSACTION;", 0, 0, 0);
        stmt_tr_count_ = 0;
    }

    stmt_tr_count_++;
}

bool SqliteBackend::setup(std::string path)
{
    if(sqlite3_open(path.c_str(), &sqlite_handle_) != SQLITE_OK) {
        std::cerr << "Error: " << sqlite3_errmsg(sqlite_handle_) << "\n";
        return false;
    }
    
    // TODO: Add error handling if database exists?
    int err = 0;

    err |= sqlite3_exec(sqlite_handle_, "CREATE TABLE branches (id INTEGR NOT NULL PRIMARY KEY, type INTEGER, source INTEGER, destination INTEGER);", 0, 0, 0);
    err |= sqlite3_exec(sqlite_handle_, "CREATE TABLE mappings (id INTEGER NOT NULL PRIMARY KEY, filename TEXT, start INTEGER, end INTEGER);", 0, 0, 0);
    err |= sqlite3_exec(sqlite_handle_, "CREATE TABLE hitcounts (id INTEGER NOT NULL PRIMARY KEY, address INTEGER, hitcount INTEGER);", 0, 0, 0);

    if(err != 0) {
        std::cerr << "Error: " << sqlite3_errmsg(sqlite_handle_) << "\n";
        return false;
    }

    err = 0;

    err |= sqlite3_prepare_v2(sqlite_handle_, "INSERT INTO branches (id, type, source, destination) VALUES (?1, ?2, ?3, ?4);", -1, &branch_ins_handle_, NULL);
    err |= sqlite3_prepare_v2(sqlite_handle_, "INSERT INTO mappings (id, filename, start, end) VALUES (?1, ?2, ?3, ?4);", -1, &mapping_ins_handle_, NULL);
    err |= sqlite3_prepare_v2(sqlite_handle_, "INSERT INTO hitcounts (id, address, hitcount) VALUES (?1, ?2, ?3);", -1, &hitcount_ins_handle_, NULL);

    if(err != 0) {
        std::cerr << "Error: " << sqlite3_errmsg(sqlite_handle_) << "\n";
    }

    return true;
}

SqliteBackend::~SqliteBackend()
{
    // Flush the current data
    sqlite3_exec(sqlite_handle_, "END TRANSACTION;", 0, 0, 0);

    // Free the prepared statements
    if(branch_ins_handle_)
        sqlite3_finalize(branch_ins_handle_);

    if(mapping_ins_handle_)
        sqlite3_finalize(mapping_ins_handle_);

    if(hitcount_ins_handle_)
        sqlite3_finalize(hitcount_ins_handle_);

    // Log the hitcount
    // Close the database
    sqlite3_close(sqlite_handle_);
}

void SqliteBackend::handle_branch(trace::BranchEvent* branch)
{
    check_flush();

    sqlite3_bind_int(branch_ins_handle_, 1, primary_key_++);
    sqlite3_bind_int(branch_ins_handle_, 2, branch->type());
    sqlite3_bind_int64(branch_ins_handle_, 3, branch->source());
    sqlite3_bind_int64(branch_ins_handle_, 4, branch->destination());

    if(sqlite3_step(branch_ins_handle_) != SQLITE_DONE) {
        std::cerr << "Branch insert: " << sqlite3_errmsg(sqlite_handle_) << "\n";
    }

    sqlite3_reset(branch_ins_handle_);
}

void SqliteBackend::handle_mapping(trace::MappingEvent* mapping)
{
    check_flush();

    sqlite3_bind_int(mapping_ins_handle_, 1, primary_key_++);
    sqlite3_bind_text(mapping_ins_handle_, 2, mapping->filename().c_str(),
            -1, NULL);
    sqlite3_bind_int64(mapping_ins_handle_, 3, mapping->start());
    sqlite3_bind_int64(mapping_ins_handle_, 4, 
            mapping->start() + mapping->size());

    if(sqlite3_step(mapping_ins_handle_) != SQLITE_DONE) {
        std::cerr << "Mapping insert: " << sqlite3_errmsg(sqlite_handle_) << "\n";
    }

    sqlite3_reset(mapping_ins_handle_);
}

void SqliteBackend::handle_hitcount(trace::HitcountEvent* hit)
{
    check_flush();

    sqlite3_bind_int(hitcount_ins_handle_, 1, primary_key_++);
    sqlite3_bind_int64(hitcount_ins_handle_, 2, hit->address());
    sqlite3_bind_int64(hitcount_ins_handle_, 3, hit->count());

    if(sqlite3_step(hitcount_ins_handle_) != SQLITE_DONE) {
        std::cerr << "Hitcount insert: " << sqlite3_errmsg(sqlite_handle_) << "\n";
    }

    sqlite3_reset(hitcount_ins_handle_);
}
