/*
 * Batch D: Partitioned Verification Test Harness
 *
 * 61 tests covering:
 *   Group A: Part-2 vs Mono-16 equivalence (14 tests)
 *   Group B: Part-2 functional + deny-by-default (7 tests)
 *   Group C: Part-4 functional (12 tests)
 *   Group D: Part-8 functional (12 tests)
 *   Group E: Part-16 functional (12 tests)
 *   Group F: Short-circuit & boundary (4 tests)
 *
 * The partitioned scheme: D_part = V_univ(s) AND (V_0 OR V_1 OR ... OR V_{n-1})
 * where each V_j is a verified EverParse validator over a 55-byte buffer.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "generated/PartAccess8Wrapper.h"
#include "generated/UnivRateWrapper.h"
#include "generated/MonoAccess16Wrapper.h"

/* ---- Error callbacks (required by EverParse) ---- */

void PartAccess8EverParseError(
    const char *struct_name, const char *field_name, const char *reason)
{
    (void)struct_name; (void)field_name; (void)reason;
}

void UnivRateEverParseError(
    const char *struct_name, const char *field_name, const char *reason)
{
    (void)struct_name; (void)field_name; (void)reason;
}

void MonoAccess16EverParseError(
    const char *struct_name, const char *field_name, const char *reason)
{
    (void)struct_name; (void)field_name; (void)reason;
}

/* ---- Constants ---- */

#define K               8       /* rules per partition */
#define PART_BUF_SIZE   55      /* K*6 + 4 + 1 + 1 + 1 */
#define UNIV_BUF_SIZE   2
#define MONO16_RULES    16
#define MONO16_BUF_SIZE 105     /* 16*6 + 4 + 1 + 1 + 1 + 1 + 1 */
#define MAX_PARTITIONS  16
#define MAX_RULES       (MAX_PARTITIONS * K)

#define METHOD_GET   1
#define METHOD_POST  2

#define ROLE_NONE      0
#define ROLE_OPERATOR  1
#define ROLE_ADMIN     2

#define PATH_A      0xAAAAAAAAu
#define PATH_B      0xBBBBBBBBu
#define PATH_C      0xCCCCCCCCu
#define PATH_D      0xDDDDDDDDu
#define PATH_E      0xEEEEEEEEu
#define DEAD_HASH   0xDEADDEADu

#define RATE_OK     5
#define RATE_OVER   99

/* ---- Rule type ---- */

typedef struct {
    uint32_t path_hash;
    uint8_t  method;
    uint8_t  min_role;
} Rule;

/* ---- Byte helpers (little-endian, fixed-offset) ---- */

static void write_u32(uint8_t *buf, int off, uint32_t v)
{
    buf[off + 0] = (uint8_t)((v >>  0) & 0xFF);
    buf[off + 1] = (uint8_t)((v >>  8) & 0xFF);
    buf[off + 2] = (uint8_t)((v >> 16) & 0xFF);
    buf[off + 3] = (uint8_t)((v >> 24) & 0xFF);
}

static void write_rule(uint8_t *buf, int off, const Rule *r)
{
    write_u32(buf, off, r->path_hash);
    buf[off + 4] = r->method;
    buf[off + 5] = r->min_role;
}

/* ---- Glue functions (the code under audit) ---- */

/*
 * Partitioned evaluation: V_univ(rate) AND (V_0 OR V_1 OR ... OR V_{n-1})
 *
 * Trust-relevant lines: buffer construction (Category A, same as A2)
 *                       + boolean OR loop (Category B, 3 new lines).
 */
static BOOLEAN run_partitioned(int n, const Rule *rules,
                               uint32_t req_path, uint8_t req_method,
                               uint8_t auth_state, uint8_t rate_count)
{
    /* Universal constraint (Category C: 2-line buffer construction) */
    uint8_t univ_buf[UNIV_BUF_SIZE];
    univ_buf[0] = rate_count;
    univ_buf[1] = 0;
    if (!UnivRateCheckUnivRate(univ_buf, UNIV_BUF_SIZE))
        return FALSE;

    /* Short-circuit OR over n partitions (Category B: boolean composition) */
    for (int j = 0; j < n; j++) {
        /* Category A: per-partition buffer construction (same pattern as A2) */
        uint8_t part_buf[PART_BUF_SIZE];
        memset(part_buf, 0, PART_BUF_SIZE);
        for (int r = 0; r < K; r++)
            write_rule(part_buf, r * 6, &rules[j * K + r]);
        write_u32(part_buf, K * 6, req_path);
        part_buf[K * 6 + 4] = req_method;
        part_buf[K * 6 + 5] = auth_state;
        /* part_buf[54] = phantom _access_ok byte */

        if (PartAccess8CheckPartAccess8(part_buf, PART_BUF_SIZE))
            return TRUE;    /* short-circuit: match found */
    }
    return FALSE;   /* deny-by-default: no partition accepted */
}

/*
 * Monolithic 16-rule evaluation (for equivalence comparison).
 * Layout: 16*6 rules + 4 req_path + 1 req_method + 1 auth_state
 *         + 1 rate_count + 1 _rate_ok + 1 _access_ok = 105 bytes.
 */
static BOOLEAN run_mono16(const Rule *rules,
                          uint32_t req_path, uint8_t req_method,
                          uint8_t auth_state, uint8_t rate_count)
{
    uint8_t buf[MONO16_BUF_SIZE];
    memset(buf, 0, MONO16_BUF_SIZE);
    for (int r = 0; r < MONO16_RULES; r++)
        write_rule(buf, r * 6, &rules[r]);
    int off = MONO16_RULES * 6;    /* 96 */
    write_u32(buf, off, req_path);
    buf[off + 4] = req_method;
    buf[off + 5] = auth_state;
    buf[off + 6] = rate_count;
    /* buf[off + 7] = phantom _rate_ok */
    /* buf[off + 8] = phantom _access_ok */
    return MonoAccess16CheckMonoAccess16(buf, MONO16_BUF_SIZE);
}

/* ---- Test infrastructure ---- */

static int g_passed = 0;
static int g_total  = 0;

static void check(const char *group, int id, const char *desc,
                   BOOLEAN got, BOOLEAN expected)
{
    g_total++;
    if (got == expected) {
        printf("  PASS  %s%02d: %s\n", group, id, desc);
        g_passed++;
    } else {
        printf("  FAIL  %s%02d: %s (expected %s, got %s)\n",
               group, id, desc,
               expected ? "ACCEPT" : "DENY",
               got      ? "ACCEPT" : "DENY");
    }
}

/* Equivalence check: both partitioned and monolithic must agree and match expected */
static void check_equiv(int id, const char *desc,
                         const Rule *rules, int n,
                         uint32_t req_path, uint8_t req_method,
                         uint8_t auth_state, uint8_t rate_count,
                         BOOLEAN expected)
{
    BOOLEAN part_result = run_partitioned(n, rules, req_path, req_method,
                                          auth_state, rate_count);
    BOOLEAN mono_result = run_mono16(rules, req_path, req_method,
                                      auth_state, rate_count);
    g_total++;
    if (part_result == expected && mono_result == expected) {
        printf("  PASS  A%02d: %s  [Part-2=%s Mono-16=%s]\n",
               id, desc,
               part_result ? "ACCEPT" : "DENY",
               mono_result ? "ACCEPT" : "DENY");
        g_passed++;
    } else {
        printf("  FAIL  A%02d: %s  [Part-2=%s Mono-16=%s expected=%s]\n",
               id, desc,
               part_result ? "ACCEPT" : "DENY",
               mono_result ? "ACCEPT" : "DENY",
               expected    ? "ACCEPT" : "DENY");
    }
}

/* ---- Policy helpers ---- */

static void fill_dead(Rule *rules, int count)
{
    for (int i = 0; i < count; i++) {
        rules[i].path_hash = DEAD_HASH;
        rules[i].method    = 0;
        rules[i].min_role  = 0;
    }
}

static void set_rule(Rule *rules, int idx,
                     uint32_t path, uint8_t method, uint8_t min_role)
{
    rules[idx].path_hash = path;
    rules[idx].method    = method;
    rules[idx].min_role  = min_role;
}

/* ---- Test Groups ---- */

/*
 * Group A: Part-2 vs Mono-16 Equivalence (14 tests)
 *
 * Policy: 16 rules split into 2 partitions of 8.
 *   Rule 0:  PATH_A, GET, OPERATOR   (partition 0)
 *   Rule 4:  PATH_B, POST, ADMIN     (partition 0)
 *   Rule 8:  PATH_C, GET, OPERATOR   (partition 1)
 *   Rule 12: PATH_D, POST, NONE      (partition 1)
 *   All others: DEAD_HASH
 */
static void group_a(void)
{
    Rule rules[16];
    fill_dead(rules, 16);
    set_rule(rules, 0,  PATH_A, METHOD_GET,  ROLE_OPERATOR);
    set_rule(rules, 4,  PATH_B, METHOD_POST, ROLE_ADMIN);
    set_rule(rules, 8,  PATH_C, METHOD_GET,  ROLE_OPERATOR);
    set_rule(rules, 12, PATH_D, METHOD_POST, ROLE_NONE);

    printf("\n=== Group A: Part-2 vs Mono-16 Equivalence (14 tests) ===\n");

    /* Accept tests */
    check_equiv(1, "ACCEPT GET PATH_A as OPERATOR (rule 0, part 0)",
                rules, 2, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK, TRUE);
    check_equiv(2, "ACCEPT POST PATH_B as ADMIN (rule 4, part 0)",
                rules, 2, PATH_B, METHOD_POST, ROLE_ADMIN, RATE_OK, TRUE);
    check_equiv(3, "ACCEPT GET PATH_C as OPERATOR (rule 8, part 1)",
                rules, 2, PATH_C, METHOD_GET, ROLE_OPERATOR, RATE_OK, TRUE);
    check_equiv(4, "ACCEPT POST PATH_D as NONE (rule 12, part 1)",
                rules, 2, PATH_D, METHOD_POST, ROLE_NONE, RATE_OK, TRUE);
    check_equiv(5, "ACCEPT GET PATH_A as ADMIN (admin >= operator)",
                rules, 2, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OK, TRUE);
    check_equiv(6, "ACCEPT GET PATH_C as ADMIN (admin >= operator, part 1)",
                rules, 2, PATH_C, METHOD_GET, ROLE_ADMIN, RATE_OK, TRUE);
    check_equiv(7, "ACCEPT POST PATH_D as ADMIN (admin >= none)",
                rules, 2, PATH_D, METHOD_POST, ROLE_ADMIN, RATE_OK, TRUE);
    check_equiv(8, "ACCEPT POST PATH_D as OPERATOR (operator >= none)",
                rules, 2, PATH_D, METHOD_POST, ROLE_OPERATOR, RATE_OK, TRUE);

    /* Deny tests */
    check_equiv(9, "DENY GET PATH_E (no path match)",
                rules, 2, PATH_E, METHOD_GET, ROLE_ADMIN, RATE_OK, FALSE);
    check_equiv(10, "DENY POST PATH_A (wrong method for rule 0)",
                rules, 2, PATH_A, METHOD_POST, ROLE_ADMIN, RATE_OK, FALSE);
    check_equiv(11, "DENY GET PATH_B (wrong method for rule 4)",
                rules, 2, PATH_B, METHOD_GET, ROLE_ADMIN, RATE_OK, FALSE);
    check_equiv(12, "DENY GET PATH_A as NONE (insufficient role)",
                rules, 2, PATH_A, METHOD_GET, ROLE_NONE, RATE_OK, FALSE);
    check_equiv(13, "DENY rate exceeded despite rule match",
                rules, 2, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OVER, FALSE);
    check_equiv(14, "ACCEPT rate OK with rule match",
                rules, 2, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK, TRUE);
}

/*
 * Group B: Part-2 Deny-by-Default + Functional (7 tests)
 */
static void group_b(void)
{
    Rule rules[16];
    BOOLEAN result;

    printf("\n=== Group B: Part-2 Deny-by-Default & Functional (7 tests) ===\n");

    /* B01-B02: All-dead deny-by-default */
    fill_dead(rules, 16);

    result = run_partitioned(2, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("B", 1, "all-dead 2 partitions, rate OK -> DENY", result, FALSE);

    result = run_partitioned(2, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OVER);
    check("B", 2, "all-dead 2 partitions, rate exceeded -> DENY", result, FALSE);

    /* B03-B05: Single active rule boundary positions */
    fill_dead(rules, 16);
    set_rule(rules, 7, PATH_A, METHOD_GET, ROLE_OPERATOR);

    result = run_partitioned(2, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("B", 3, "rule 7 (last in part 0) -> ACCEPT", result, TRUE);

    fill_dead(rules, 16);
    set_rule(rules, 8, PATH_A, METHOD_GET, ROLE_OPERATOR);

    result = run_partitioned(2, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("B", 4, "rule 8 (first in part 1) -> ACCEPT", result, TRUE);

    fill_dead(rules, 16);
    set_rule(rules, 15, PATH_A, METHOD_GET, ROLE_OPERATOR);

    result = run_partitioned(2, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("B", 5, "rule 15 (last in part 1) -> ACCEPT", result, TRUE);

    /* B06-B07: Universal constraint separaton */
    fill_dead(rules, 16);
    set_rule(rules, 0, PATH_A, METHOD_GET, ROLE_OPERATOR);

    result = run_partitioned(2, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OVER);
    check("B", 6, "rate exceeded overrides access match -> DENY", result, FALSE);

    result = run_partitioned(2, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, 49);
    check("B", 7, "rate=49 (just under limit) + match -> ACCEPT", result, TRUE);
}

/*
 * Group C: Part-4 Functional (12 tests)
 *
 * 32 rules = 4 partitions x 8 rules.
 * Active rules spread across all 4 partitions.
 */
static void group_c(void)
{
    Rule rules[32];
    BOOLEAN result;

    printf("\n=== Group C: Part-4 Functional (12 tests) ===\n");

    fill_dead(rules, 32);
    set_rule(rules, 0,  PATH_A, METHOD_GET,  ROLE_OPERATOR);   /* part 0 */
    set_rule(rules, 8,  PATH_B, METHOD_POST, ROLE_ADMIN);      /* part 1 */
    set_rule(rules, 16, PATH_C, METHOD_GET,  ROLE_NONE);       /* part 2 */
    set_rule(rules, 24, PATH_D, METHOD_POST, ROLE_OPERATOR);   /* part 3 */

    /* Accept: match in each partition */
    result = run_partitioned(4, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("C", 1, "match in partition 0", result, TRUE);

    result = run_partitioned(4, rules, PATH_B, METHOD_POST, ROLE_ADMIN, RATE_OK);
    check("C", 2, "match in partition 1", result, TRUE);

    result = run_partitioned(4, rules, PATH_C, METHOD_GET, ROLE_NONE, RATE_OK);
    check("C", 3, "match in partition 2 (NONE >= NONE)", result, TRUE);

    result = run_partitioned(4, rules, PATH_D, METHOD_POST, ROLE_OPERATOR, RATE_OK);
    check("C", 4, "match in partition 3", result, TRUE);

    /* Accept: role hierarchy */
    result = run_partitioned(4, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("C", 5, "admin >= operator in partition 0", result, TRUE);

    result = run_partitioned(4, rules, PATH_C, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("C", 6, "admin >= none in partition 2", result, TRUE);

    /* Deny tests */
    result = run_partitioned(4, rules, PATH_E, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("C", 7, "no path match across 4 partitions", result, FALSE);

    result = run_partitioned(4, rules, PATH_A, METHOD_POST, ROLE_ADMIN, RATE_OK);
    check("C", 8, "wrong method (POST for GET-only rule)", result, FALSE);

    result = run_partitioned(4, rules, PATH_B, METHOD_POST, ROLE_OPERATOR, RATE_OK);
    check("C", 9, "insufficient role (OPERATOR < ADMIN)", result, FALSE);

    result = run_partitioned(4, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OVER);
    check("C", 10, "rate exceeded overrides match", result, FALSE);

    /* Deny-by-default: all dead across 4 partitions */
    fill_dead(rules, 32);
    result = run_partitioned(4, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("C", 11, "all-dead 4 partitions -> DENY", result, FALSE);

    result = run_partitioned(4, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OVER);
    check("C", 12, "all-dead 4 partitions + rate exceeded -> DENY", result, FALSE);
}

/*
 * Group D: Part-8 Functional (12 tests)
 *
 * 64 rules = 8 partitions x 8 rules.
 */
static void group_d(void)
{
    Rule rules[64];
    BOOLEAN result;

    printf("\n=== Group D: Part-8 Functional (12 tests) ===\n");

    fill_dead(rules, 64);
    set_rule(rules, 0,  PATH_A, METHOD_GET,  ROLE_OPERATOR);   /* part 0 */
    set_rule(rules, 24, PATH_B, METHOD_POST, ROLE_ADMIN);      /* part 3 */
    set_rule(rules, 56, PATH_C, METHOD_GET,  ROLE_NONE);       /* part 7 */

    /* Accept: match in different partitions */
    result = run_partitioned(8, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("D", 1, "match in partition 0", result, TRUE);

    result = run_partitioned(8, rules, PATH_B, METHOD_POST, ROLE_ADMIN, RATE_OK);
    check("D", 2, "match in partition 3 (middle)", result, TRUE);

    result = run_partitioned(8, rules, PATH_C, METHOD_GET, ROLE_NONE, RATE_OK);
    check("D", 3, "match in partition 7 (last)", result, TRUE);

    /* Role hierarchy */
    result = run_partitioned(8, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("D", 4, "admin >= operator in partition 0", result, TRUE);

    result = run_partitioned(8, rules, PATH_C, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("D", 5, "admin >= none in partition 7", result, TRUE);

    result = run_partitioned(8, rules, PATH_B, METHOD_POST, ROLE_ADMIN, RATE_OK);
    check("D", 6, "admin matches admin in partition 3", result, TRUE);

    /* Deny tests */
    result = run_partitioned(8, rules, PATH_E, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("D", 7, "no path match across 8 partitions", result, FALSE);

    result = run_partitioned(8, rules, PATH_A, METHOD_POST, ROLE_ADMIN, RATE_OK);
    check("D", 8, "wrong method", result, FALSE);

    result = run_partitioned(8, rules, PATH_B, METHOD_POST, ROLE_OPERATOR, RATE_OK);
    check("D", 9, "insufficient role", result, FALSE);

    result = run_partitioned(8, rules, PATH_C, METHOD_GET, ROLE_NONE, RATE_OVER);
    check("D", 10, "rate exceeded overrides match", result, FALSE);

    /* Deny-by-default */
    fill_dead(rules, 64);
    result = run_partitioned(8, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("D", 11, "all-dead 8 partitions -> DENY", result, FALSE);

    result = run_partitioned(8, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OVER);
    check("D", 12, "all-dead 8 partitions + rate exceeded -> DENY", result, FALSE);
}

/*
 * Group E: Part-16 Functional (12 tests)
 *
 * 128 rules = 16 partitions x 8 rules.
 */
static void group_e(void)
{
    Rule rules[128];
    BOOLEAN result;

    printf("\n=== Group E: Part-16 Functional (12 tests) ===\n");

    fill_dead(rules, 128);
    set_rule(rules, 0,   PATH_A, METHOD_GET,  ROLE_OPERATOR);  /* part 0 */
    set_rule(rules, 56,  PATH_B, METHOD_POST, ROLE_ADMIN);     /* part 7 */
    set_rule(rules, 120, PATH_C, METHOD_GET,  ROLE_NONE);      /* part 15 */

    /* Accept: match in different partitions */
    result = run_partitioned(16, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("E", 1, "match in partition 0", result, TRUE);

    result = run_partitioned(16, rules, PATH_B, METHOD_POST, ROLE_ADMIN, RATE_OK);
    check("E", 2, "match in partition 7 (middle)", result, TRUE);

    result = run_partitioned(16, rules, PATH_C, METHOD_GET, ROLE_NONE, RATE_OK);
    check("E", 3, "match in partition 15 (last)", result, TRUE);

    /* Role hierarchy */
    result = run_partitioned(16, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("E", 4, "admin >= operator in partition 0", result, TRUE);

    result = run_partitioned(16, rules, PATH_C, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("E", 5, "admin >= none in partition 15", result, TRUE);

    result = run_partitioned(16, rules, PATH_B, METHOD_POST, ROLE_ADMIN, RATE_OK);
    check("E", 6, "admin matches admin in partition 7", result, TRUE);

    /* Deny tests */
    result = run_partitioned(16, rules, PATH_E, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("E", 7, "no path match across 16 partitions", result, FALSE);

    result = run_partitioned(16, rules, PATH_A, METHOD_POST, ROLE_ADMIN, RATE_OK);
    check("E", 8, "wrong method", result, FALSE);

    result = run_partitioned(16, rules, PATH_B, METHOD_POST, ROLE_OPERATOR, RATE_OK);
    check("E", 9, "insufficient role", result, FALSE);

    result = run_partitioned(16, rules, PATH_C, METHOD_GET, ROLE_NONE, RATE_OVER);
    check("E", 10, "rate exceeded overrides match", result, FALSE);

    /* Deny-by-default */
    fill_dead(rules, 128);
    result = run_partitioned(16, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OK);
    check("E", 11, "all-dead 16 partitions -> DENY", result, FALSE);

    result = run_partitioned(16, rules, PATH_A, METHOD_GET, ROLE_ADMIN, RATE_OVER);
    check("E", 12, "all-dead 16 partitions + rate exceeded -> DENY", result, FALSE);
}

/*
 * Group F: Short-circuit & Boundary (4 tests)
 */
static void group_f(void)
{
    Rule rules[128];
    BOOLEAN result;

    printf("\n=== Group F: Short-circuit & Boundary (4 tests) ===\n");

    /* F01: Part-2, match in both partitions (still accept) */
    fill_dead(rules, 16);
    set_rule(rules, 0, PATH_A, METHOD_GET, ROLE_OPERATOR);
    set_rule(rules, 8, PATH_A, METHOD_GET, ROLE_OPERATOR);
    result = run_partitioned(2, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("F", 1, "Part-2 match in both partitions -> ACCEPT", result, TRUE);

    /* F02: Part-4, match in partition 0 (short-circuit, others dead) */
    fill_dead(rules, 32);
    set_rule(rules, 0, PATH_A, METHOD_GET, ROLE_OPERATOR);
    result = run_partitioned(4, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("F", 2, "Part-4 short-circuit in partition 0", result, TRUE);

    /* F03: Part-16, single rule at rule 127 (last rule of last partition) */
    fill_dead(rules, 128);
    set_rule(rules, 127, PATH_A, METHOD_GET, ROLE_OPERATOR);
    result = run_partitioned(16, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("F", 3, "Part-16 rule 127 (last of last partition)", result, TRUE);

    /* F04: Part-8, match in multiple partitions (correctness) */
    fill_dead(rules, 64);
    set_rule(rules, 0,  PATH_A, METHOD_GET, ROLE_OPERATOR);
    set_rule(rules, 24, PATH_A, METHOD_GET, ROLE_OPERATOR);
    set_rule(rules, 56, PATH_A, METHOD_GET, ROLE_OPERATOR);
    result = run_partitioned(8, rules, PATH_A, METHOD_GET, ROLE_OPERATOR, RATE_OK);
    check("F", 4, "Part-8 match in partitions 0,3,7 -> ACCEPT", result, TRUE);
}

/* ---- Main ---- */

int main(void)
{
    printf("=== Batch D: Partitioned Verification Tests ===\n");

    group_a();
    group_b();
    group_c();
    group_d();
    group_e();
    group_f();

    printf("\n=== Results: %d/%d passed ===\n", g_passed, g_total);
    return (g_passed == g_total) ? 0 : 1;
}
