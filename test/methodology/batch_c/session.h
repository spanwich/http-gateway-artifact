/*
 * Batch C: Session Table
 *
 * Linear-scan session table for multi-client pipeline.
 * Self-contained — no domain constants needed.
 */

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

#define MAX_SESSIONS 8

typedef struct {
    uint8_t  active;       /* 0=free, 1=in-use */
    uint32_t client_id;    /* 0=invalid */
    uint8_t  auth_state;
    uint8_t  rate_count;
} SessionEntry;

typedef struct {
    SessionEntry entries[MAX_SESSIONS];
} SessionTable;

void         session_table_init(SessionTable *t);
SessionEntry *session_lookup(SessionTable *t, uint32_t client_id);
SessionEntry *session_create(SessionTable *t, uint32_t client_id);
int          session_destroy(SessionTable *t, uint32_t client_id);
int          session_count_active(const SessionTable *t);

#endif /* SESSION_H */
