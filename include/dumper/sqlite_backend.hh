#ifndef SQLITE_BACKEND_HH
#define SQLITE_BACKEND_HH

#include <map>
#include <string>
#include <cstdint>
#include <sqlite3.h>

#include "dumper/streaming_backend.hh"
#include "trace.pb.h"

class SqliteBackend: public StreamingBackend {
    public:
    SqliteBackend(std::string path);
    ~SqliteBackend();

    void handle_branch(trace::BranchEvent* branch) override;
    void handle_mapping(trace::MappingEvent* mapping) override;

    private:
    sqlite3* sqlite_handle_;
    std::map<uint64_t, size_t> bb_hitcount_;
};

#endif
