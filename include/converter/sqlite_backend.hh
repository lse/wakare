#ifndef SQLITE_BACKEND_HH
#define SQLITE_BACKEND_HH

#include <string>
#include <sqlite3.h>

#include "converter/streaming_backend.hh"
#include "trace.pb.h"

class SqliteBackend: public StreamingBackend {
    public:
    SqliteBackend(std::string path);
    ~SqliteBackend();

    void handle_branch(trace::BranchEvent* branch) override;
    void handle_mapping(trace::MappingEvent* mapping) override;
    void handle_hitcount(trace::HitcountEvent* hit) override;

    private:
    sqlite3* sqlite_handle_;
};

#endif
