#ifndef SQLITE_BACKEND_HH
#define SQLITE_BACKEND_HH

#include <string>
#include <sqlite3.h>

#include "converter/streaming_backend.hh"
#include "trace.pb.h"

// Commit a transaction every N operations
#define COMMIT_THRESHOLD 65536

class SqliteBackend: public StreamingBackend {
    public:
    SqliteBackend() = default;
    ~SqliteBackend();

    bool setup(std::string outpath) override;
    void handle_branch(trace::BranchEvent* branch) override;
    void handle_mapping(trace::MappingEvent* mapping) override;
    void handle_hitcount(trace::HitcountEvent* hit) override;

    private:
    void check_flush();

    int stmt_tr_count_ = 0; // number of operations in the transaction
    int branch_index_ = 0;
    int primary_key_ = 0;
    sqlite3* sqlite_handle_;
    sqlite3_stmt* branch_ins_handle_ = nullptr;
    sqlite3_stmt* mapping_ins_handle_ = nullptr;
    sqlite3_stmt* hitcount_ins_handle_ = nullptr;
};

#endif
