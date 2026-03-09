/*
 * Standalone unit tests for RateLimiter logic.
 *
 * Tests the rate table in isolation (no CAmkES, no dataport).
 * 8 tests covering: new subject, repeat, different subject,
 * saturation at MAX_RATE, 51st request denied, table full, reset, post-reset.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ---- Inline rate limiter logic (matching RateLimiter.c) ---- */

#define MAX_SUBJECTS  16
#define MAX_RATE      50

typedef struct {
    uint8_t  active;
    uint8_t  subject_id_len;
    uint8_t  subject_id[32];
    uint8_t  count;
} RateEntry;

static RateEntry rate_table[MAX_SUBJECTS];

static int subject_match(const RateEntry *entry, const uint8_t *subject, uint8_t len)
{
    if (entry->subject_id_len != len) return 0;
    for (int i = 0; i < len; i++) {
        if (entry->subject_id[i] != subject[i]) return 0;
    }
    return 1;
}

static uint8_t rate_lookup(const uint8_t *subject, uint8_t sub_len)
{
    /* Look up existing entry */
    for (int i = 0; i < MAX_SUBJECTS; i++) {
        if (rate_table[i].active && subject_match(&rate_table[i], subject, sub_len)) {
            if (rate_table[i].count < 255) {
                rate_table[i].count++;
            }
            return rate_table[i].count;
        }
    }

    /* Not found: create new entry */
    for (int i = 0; i < MAX_SUBJECTS; i++) {
        if (!rate_table[i].active) {
            rate_table[i].active = 1;
            rate_table[i].subject_id_len = sub_len;
            memcpy(rate_table[i].subject_id, subject, sub_len);
            rate_table[i].count = 1;
            return 1;
        }
    }

    /* Table full: fail-safe deny */
    return MAX_RATE;
}

static void rate_reset(void)
{
    memset(rate_table, 0, sizeof(rate_table));
}

/* ---- Test harness ---- */

static int pass = 0, total = 0;

#define CHECK(name, cond) do { \
    total++; \
    if (cond) { \
        printf("  PASS: %s\n", name); \
        pass++; \
    } else { \
        printf("  FAIL: %s\n", name); \
    } \
} while(0)

int main(void)
{
    printf("=== RateLimiter test suite ===\n\n");

    memset(rate_table, 0, sizeof(rate_table));

    /* Test 1: New subject -> count=1 */
    {
        uint8_t count = rate_lookup((const uint8_t *)"admin", 5);
        CHECK("new subject 'admin' -> count=1", count == 1);
    }

    /* Test 2: Repeat same subject -> count=2 */
    {
        uint8_t count = rate_lookup((const uint8_t *)"admin", 5);
        CHECK("repeat 'admin' -> count=2", count == 2);
    }

    /* Test 3: Different subject -> count=1 (independent) */
    {
        uint8_t count = rate_lookup((const uint8_t *)"oper", 4);
        CHECK("different subject 'oper' -> count=1", count == 1);
    }

    /* Test 4: 50 requests total -> count=50 (48 more for admin) */
    {
        uint8_t count = 0;
        for (int i = 0; i < 48; i++) {
            count = rate_lookup((const uint8_t *)"admin", 5);
        }
        CHECK("50 requests total -> count=50", count == 50);
    }

    /* Test 5: 51st request -> count=51 (exceeds MAX_RATE) */
    {
        uint8_t count = rate_lookup((const uint8_t *)"admin", 5);
        CHECK("51st request -> count=51 (>=MAX_RATE)", count == 51 && count >= MAX_RATE);
    }

    /* Test 6: Table full -> returns MAX_RATE */
    {
        memset(rate_table, 0, sizeof(rate_table));
        char name[4];
        for (int i = 0; i < MAX_SUBJECTS; i++) {
            name[0] = 'A' + (char)(i / 26);
            name[1] = 'a' + (char)(i % 26);
            name[2] = '\0';
            rate_lookup((const uint8_t *)name, 2);
        }
        /* Table is now full; try a new subject */
        uint8_t count = rate_lookup((const uint8_t *)"NEW", 3);
        CHECK("table full -> returns MAX_RATE", count == MAX_RATE);
    }

    /* Test 7: Reset clears all */
    {
        rate_reset();
        int all_inactive = 1;
        for (int i = 0; i < MAX_SUBJECTS; i++) {
            if (rate_table[i].active) { all_inactive = 0; break; }
        }
        CHECK("reset clears all entries", all_inactive);
    }

    /* Test 8: Post-reset, new subject starts at 1 */
    {
        uint8_t count = rate_lookup((const uint8_t *)"admin", 5);
        CHECK("post-reset 'admin' -> count=1", count == 1);
    }

    printf("\n=== Results: %d/%d passed ===\n", pass, total);
    return (pass == total) ? 0 : 1;
}
