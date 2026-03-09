/*
 * RateLimiter.c -- CAmkES component: per-subject rate counter (passive)
 *
 * Provides RateIPC procedure (RPC-driven, no control thread).
 * FStarExtractor copies subject_id into rate_dp, calls rate_lookup_and_increment(),
 * and reads the count from rate_dp[0].
 *
 * Table: MAX_SUBJECTS entries, each with a subject_id hash and count.
 * Count saturates at 255 (uint8_t max).
 * Table full -> returns MAX_RATE (fail-safe deny).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <camkes.h>

#define MAX_SUBJECTS  16
#define MAX_RATE      50

/* Per-subject rate entry */
typedef struct {
    uint8_t  active;
    uint8_t  subject_id_len;
    uint8_t  subject_id[32];
    uint8_t  count;
} RateEntry;

static RateEntry rate_table[MAX_SUBJECTS];

/* Simple byte comparison for subject_id matching */
static int subject_match(const RateEntry *entry, const uint8_t *subject, uint8_t len)
{
    if (entry->subject_id_len != len) return 0;
    for (int i = 0; i < len; i++) {
        if (entry->subject_id[i] != subject[i]) return 0;
    }
    return 1;
}

/*
 * rate_lookup_and_increment(subject_id_len):
 *   - Reads subject_id from rate_dp[0..subject_id_len-1]
 *   - Looks up or creates entry in rate_table
 *   - Increments count (saturates at 255)
 *   - Writes count to rate_dp[0]
 *   - Returns response length (1)
 */
int rate_lookup_and_increment(int subject_id_len)
{
    volatile uint8_t *dp = (volatile uint8_t *)rate_dp;
    uint8_t sub_len = (uint8_t)subject_id_len;
    if (sub_len > 32) sub_len = 32;

    /* Copy subject_id from dataport to local (volatile -> local) */
    uint8_t subject[32];
    for (int i = 0; i < sub_len; i++) {
        subject[i] = dp[i];
    }

    /* Look up existing entry */
    for (int i = 0; i < MAX_SUBJECTS; i++) {
        if (rate_table[i].active && subject_match(&rate_table[i], subject, sub_len)) {
            /* Found: increment and return */
            if (rate_table[i].count < 255) {
                rate_table[i].count++;
            }
            dp[0] = rate_table[i].count;
            return 1;
        }
    }

    /* Not found: create new entry */
    for (int i = 0; i < MAX_SUBJECTS; i++) {
        if (!rate_table[i].active) {
            rate_table[i].active = 1;
            rate_table[i].subject_id_len = sub_len;
            memcpy(rate_table[i].subject_id, subject, sub_len);
            rate_table[i].count = 1;
            dp[0] = 1;
            return 1;
        }
    }

    /* Table full: fail-safe deny */
    dp[0] = MAX_RATE;
    return 1;
}

/*
 * rate_reset_all(): clear all rate counters.
 * Called periodically or on policy update.
 */
int rate_reset_all(void)
{
    memset(rate_table, 0, sizeof(rate_table));
    return 0;
}
