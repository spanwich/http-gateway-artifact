/*
 * EverParse DNF Access Control - Experiment 2 Test Harness
 *
 * Tests hybrid CNF+DNF: rate limit AND body size AND access rules
 * must ALL pass for the parse to succeed.
 *
 * Buffer layout (43 bytes, little-endian):
 *   [0]      max_rate (u8)
 *   [1..4]   max_body (u32)
 *   [5..10]  Rule 0: path_hash(u32) method(u8) min_role(u8)
 *   [11..16] Rule 1
 *   [17..22] Rule 2
 *   [23..28] Rule 3
 *   [29..34] Request: path_hash(u32) method(u8) auth_state(u8)
 *   [35]     req_rate_count (u8)
 *   [36..39] req_content_length (u32)
 *   [40]     _rate_ok byte
 *   [41]     _size_ok byte
 *   [42]     _access_ok byte
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Test2HybridWrapper.h"

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

#define BUF_SIZE 43

/* Required by EverParse generated wrapper */
void Test2HybridEverParseError(
    const char *struct_name,
    const char *field_name,
    const char *reason)
{
    (void)struct_name; (void)field_name; (void)reason;
}

/* Helper: write a u32 in little-endian */
static void write_u32(uint8_t *buf, int offset, uint32_t val)
{
    buf[offset + 0] = (val >>  0) & 0xFF;
    buf[offset + 1] = (val >>  8) & 0xFF;
    buf[offset + 2] = (val >> 16) & 0xFF;
    buf[offset + 3] = (val >> 24) & 0xFF;
}

/* Helper: write a rule (6 bytes) */
static void write_rule(uint8_t *buf, int offset,
                       uint32_t path_hash, uint8_t method, uint8_t min_role)
{
    write_u32(buf, offset, path_hash);
    buf[offset + 4] = method;
    buf[offset + 5] = min_role;
}

/* Fill standard policy: max_rate=10, max_body=4096, 4 access rules */
static void write_standard_policy(uint8_t *buf)
{
    /* Universal constraints */
    buf[0] = 10;                      /* max_rate */
    write_u32(buf, 1, 4096);          /* max_body */

    /* Access rules */
    write_rule(buf,  5, HASH_STATUS, METHOD_GET,  ROLE_OPERATOR);
    write_rule(buf, 11, HASH_STATUS, METHOD_POST, ROLE_ADMIN);
    write_rule(buf, 17, HASH_POLICY, METHOD_GET,  ROLE_ADMIN);
    write_rule(buf, 23, HASH_POLICY, METHOD_PUT,  ROLE_ADMIN);
}

/* Write request fields */
static void write_request(uint8_t *buf,
                          uint32_t path_hash, uint8_t method, uint8_t auth_state,
                          uint8_t rate_count, uint32_t content_length)
{
    write_u32(buf, 29, path_hash);
    buf[33] = method;
    buf[34] = auth_state;
    buf[35] = rate_count;
    write_u32(buf, 36, content_length);
}

static int run_test(const char *name, uint8_t *buf, uint32_t len, int expect_accept)
{
    BOOLEAN result = Test2hybridCheckTestHybrid(buf, len);
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

    printf("=== Experiment 2: Hybrid CNF+DNF ===\n\n");

    /* Test A: OPERATOR GET /status, rate=5, size=100 → all pass → ACCEPT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_STATUS, METHOD_GET, ROLE_OPERATOR, 5, 100);
    buf[40] = 0; buf[41] = 0; buf[42] = 0; /* check bytes */
    total++; passed += run_test("Test A: all constraints pass", buf, BUF_SIZE, 1);

    /* Test B: rate exceeded (rate=15 >= max_rate=10) → REJECT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_STATUS, METHOD_GET, ROLE_OPERATOR, 15, 100);
    buf[40] = 0; buf[41] = 0; buf[42] = 0;
    total++; passed += run_test("Test B: rate exceeded", buf, BUF_SIZE, 0);

    /* Test C: body size exceeded (size=5000 > max_body=4096) → REJECT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_STATUS, METHOD_GET, ROLE_OPERATOR, 5, 5000);
    buf[40] = 0; buf[41] = 0; buf[42] = 0;
    total++; passed += run_test("Test C: body size exceeded", buf, BUF_SIZE, 0);

    /* Test D: no access rule matches (unknown path) → REJECT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_UNKNOWN, METHOD_GET, ROLE_ADMIN, 5, 100);
    buf[40] = 0; buf[41] = 0; buf[42] = 0;
    total++; passed += run_test("Test D: no access rule match", buf, BUF_SIZE, 0);

    /* Test E: rate AND size both exceeded → REJECT */
    memset(buf, 0, BUF_SIZE);
    write_standard_policy(buf);
    write_request(buf, HASH_STATUS, METHOD_GET, ROLE_OPERATOR, 15, 5000);
    buf[40] = 0; buf[41] = 0; buf[42] = 0;
    total++; passed += run_test("Test E: rate and size both exceeded", buf, BUF_SIZE, 0);

    printf("\nResults: %d/%d passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
