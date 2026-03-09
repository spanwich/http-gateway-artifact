/*
 * session.h -- Session table for PolicyGate
 *
 * Adapted from ControlPlane session.h:
 *   - Uses uint8_t conn_id instead of uint32_t client_id
 *   - Phase 2: conn_id=0 for single-client demo
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

#define MAX_SESSIONS 8

typedef struct {
    uint8_t  active;       /* 0=free, 1=in-use */
    uint8_t  conn_id;      /* connection identifier */
    uint8_t  auth_state;
    uint8_t  rate_count;
} SessionEntry;

typedef struct {
    SessionEntry entries[MAX_SESSIONS];
} SessionTable;

void          session_table_init(SessionTable *t);
SessionEntry *session_lookup(SessionTable *t, uint8_t conn_id);
SessionEntry *session_create(SessionTable *t, uint8_t conn_id);
int           session_destroy(SessionTable *t, uint8_t conn_id);
int           session_count_active(const SessionTable *t);
void          session_reset_all_rate_counts(SessionTable *t);

#endif /* SESSION_H */
