/*
 * EverParse DNF Access Control - Experiment 1 Test Harness
 *
 * Tests a 4-rule disjunctive access control constraint.
 * Parse succeeds = ACCEPT, parse fails = DENY.
 *
 * Buffer layout (31 bytes, little-endian):
 *   [0..5]   Rule 0: path_hash(u32) method(u8) min_role(u8)
 *   [6..11]  Rule 1
 *   [12..17] Rule 2
 *   [18..23] Rule 3
 *   [24..29] Request: path_hash(u32) method(u8) auth_state(u8)
 *   [30]     _check byte (value irrelevant, constraint validated)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Test1DisjunctionWrapper.h"

/* Constants */
#define HASH_STATUS  0xAAAAAAAAu
#define HASH_POLICY  0xBBBBBBBBu
#define HASH_UNKNOWN 0xCCCCCCCCu
#define DEAD_HASH    0xDEADDEADu

#define METHOD_GET  1
#define METHOD_POST 2
#define METHOD_PUT  3

#define ROLE_NONE     0
#define ROLE_OPERATOR 1
#define ROLE_ADMIN    2

/* Buffer size: 4 rules * 6 bytes + 1 request * 6 bytes + 1 check byte = 31 */
#define BUF_SIZE 31

/* Required by EverParse generated wrapper */
void Test1DisjunctionEverParseError(
    const char *struct_name,
    const char *field_name,
    const char *reason)
{
    /* Silent for testing; uncomment for debugging: */
    /* fprintf(stderr, "  [EverParse] %s.%s: %s\n", struct_name, field_name, reason); */
    (void)struct_name; (void)field_name; (void)reason;
}

/* Helper: write a rule at the given offset in little-endian */
static void write_rule(uint8_t *buf, int offset,
                       uint32_t path_hash, uint8_t method, uint8_t min_role)
{
    buf[offset + 0] = (path_hash >>  0) & 0xFF;
    buf[offset + 1] = (path_hash >>  8) & 0xFF;
    buf[offset + 2] = (path_hash >> 16) & 0xFF;
    buf[offset + 3] = (path_hash >> 24) & 0xFF;
    buf[offset + 4] = method;
    buf[offset + 5] = min_role;
}

/* Helper: write the request at offset 24 */
static void write_request(uint8_t *buf,
                          uint32_t path_hash, uint8_t method, uint8_t auth_state)
{
    write_rule(buf, 24, path_hash, method, auth_state);
}

/* Standard policy: 4 rules */
static void write_standard_policy(uint8_t *buf)
{
    /* Rule 0: GET /status requires OPERATOR */
    write_rule(buf, 0, HASH_STATUS, METHOD_GET, ROLE_OPERATOR);
    /* Rule 1: POST /status requires ADMIN */
    write_rule(buf, 6, HASH_STATUS, METHOD_POST, ROLE_ADMIN);
    /* Rule 2: GET /policy requires ADMIN */
    write_rule(buf, 12, HASH_POLICY, METHOD_GET, ROLE_ADMIN);
    /* Rule 3: PUT /policy requires ADMIN */
    write_rule(buf, 18, HASH_POLICY, METHOD_PUT, ROLE_ADMIN);
}

/* Dead policy: all rules use DEAD_HASH (no request can match) */
static void write_dead_policy(uint8_t *buf)
{
    write_rule(buf,  0, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf,  6, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 12, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 18, DEAD_HASH, METHOD_GET, ROLE_NONE);
}

static int run_test(const char *name, uint8_t *buf, uint32_t len, int expect_accept)
{
    BOOLEAN result = Test1disjunctionCheckTestAccess(buf, len);
    int accepted = (result == TRUE);
    int passed = (accepted == expect_accept);

    printf("  %s: %s (expected %s, got %s)\n",
           passed ? "PASS" : "FAIL",
           name,
           expect_accept ? "ACCEPT" : "REJECT",
           accepted ? "ACCEPT" : "REJECT");

    return passed;
}

int main(void)
{
    uint8_t buf[BUF_SIZE];
    int passed = 0, total = 0;

    printf("=== Experiment 1: Disjunctive Access Control ===\n\n");

    /* Test A: OPERATOR GET /status → should match Rule 0 → ACCEPT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_STATUS, METHOD_GET, ROLE_OPERATOR);
    buf[30] = 0x00; /* _check byte, value irrelevant */
    total++; passed += run_test("Test A: OPERATOR GET /status (rule 0 match)", buf, BUF_SIZE, 1);

    /* Test B: OPERATOR GET /unknown → no rule matches → REJECT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_UNKNOWN, METHOD_GET, ROLE_OPERATOR);
    buf[30] = 0x00;
    total++; passed += run_test("Test B: OPERATOR GET /unknown (no match)", buf, BUF_SIZE, 0);

    /* Test C: NONE GET /status → role too low for Rule 0 → REJECT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_STATUS, METHOD_GET, ROLE_NONE);
    buf[30] = 0x00;
    total++; passed += run_test("Test C: NONE GET /status (insufficient auth)", buf, BUF_SIZE, 0);

    /* Test D: ADMIN POST /status → should match Rule 1 → ACCEPT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_STATUS, METHOD_POST, ROLE_ADMIN);
    buf[30] = 0x00;
    total++; passed += run_test("Test D: ADMIN POST /status (rule 1 match)", buf, BUF_SIZE, 1);

    /* Test E: all-DEAD-rules deny-by-default → REJECT */
    memset(buf, 0, BUF_SIZE);
    write_dead_policy(buf);
    write_request(buf, HASH_STATUS, METHOD_GET, ROLE_ADMIN);
    buf[30] = 0x00;
    total++; passed += run_test("Test E: all-dead rules (deny-by-default)", buf, BUF_SIZE, 0);

    printf("\nResults: %d/%d passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
