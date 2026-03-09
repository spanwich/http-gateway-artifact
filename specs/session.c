/*
 * Batch C: Session Table Implementation
 *
 * Linear scan, MAX_SESSIONS=8 slots.
 * session_create is idempotent (returns existing if found).
 * session_destroy marks slot inactive via memset.
 */

#include "session.h"
#include <string.h>

void session_table_init(SessionTable *t)
{
    memset(t, 0, sizeof(*t));
}

SessionEntry *session_lookup(SessionTable *t, uint32_t client_id)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (t->entries[i].active && t->entries[i].client_id == client_id) {
            return &t->entries[i];
        }
    }
    return NULL;
}

SessionEntry *session_create(SessionTable *t, uint32_t client_id)
{
    /* Idempotent: return existing entry if found */
    SessionEntry *existing = session_lookup(t, client_id);
    if (existing) return existing;

    /* Find a free slot */
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!t->entries[i].active) {
            t->entries[i].active = 1;
            t->entries[i].client_id = client_id;
            t->entries[i].auth_state = 0;
            t->entries[i].rate_count = 0;
            return &t->entries[i];
        }
    }
    return NULL; /* table full */
}

int session_destroy(SessionTable *t, uint32_t client_id)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (t->entries[i].active && t->entries[i].client_id == client_id) {
            memset(&t->entries[i], 0, sizeof(SessionEntry));
            return 1;
        }
    }
    return 0;
}

int session_count_active(const SessionTable *t)
{
    int count = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (t->entries[i].active) count++;
    }
    return count;
}
