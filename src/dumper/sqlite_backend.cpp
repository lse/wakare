#include <map>
#include <string>
#include <cstdint>
#include <sqlite3.h>
#include "dumper/sqlite_backend.hh"

SqliteBackend::SqliteBackend(std::string path)
{
    // TODO: Maybe raise exception on error
    if(sqlite3_open(path.c_str(), &sqlite_handle_) != SQLITE_OK)
        return;
    
    // TODO: Add error handling if database exists?
    sqlite3_exec(sqlite_handle_, "create table branches (id integer not null primary key, type integer, source integer, destination integer);", 0, 0, 0);
    sqlite3_exec(sqlite_handle_, "create table mappings (id integer not null primary key, filename text, start integer, end integer);", 0, 0, 0);
    sqlite3_exec(sqlite_handle_, "create table hitcounts (id integer not null primary key, address integer, hitcount interger);", 0, 0, 0);
}

SqliteBackend::~SqliteBackend()
{
    // Flush the current data
    sqlite3_exec(sqlite_handle_, "COMMIT;", 0, 0, 0);

    // Log the hitcount
    // Close the database
    sqlite3_close(sqlite_handle_);
}

void SqliteBackend::handle_branch(trace::BranchEvent* branch)
{
    // Computing the bb hitcounts
    if(bb_hitcount_.find(branch->destination()) == bb_hitcount_.end()) {
        bb_hitcount_[branch->destination()] = 1;
    } else {
        bb_hitcount_[branch->destination()]++;
    }
}

void SqliteBackend::handle_mapping(trace::MappingEvent* mapping)
{
    
}
