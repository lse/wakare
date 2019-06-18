#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

typedef enum ip_update_type_e {
    INS_JMP,
    INS_JMP_IND,
    INS_JCC,
    INS_CALL,
    INS_CALL_IND,
    INS_RET,
    INS_INVALID
} ip_update_type;

typedef struct ip_update_s {
    uint64_t address;
    uint64_t target_ok;     // Used for conditional and direct jumps
    uint64_t target_fail;   // Used for conditional jumps
    ip_update_type type;
} ip_update;

#endif
