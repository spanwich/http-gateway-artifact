/*
 * EverParse DNF Access Control - Experiment 3 Test Harness
 *
 * Dynamic policy update: same validator binary (Test2Hybrid), same request
 * (OPERATOR GET /status, rate=5, size=100), three different policies.
 * Demonstrates that policy is data while enforcement is verified code.
 *
 * Reuses Test2Hybrid validator — no new .3d spec needed.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Test2HybridWrapper.h"

/* Constants */
#define HASH_STATUS  0xAAAAAAAAu
#define DEAD_HASH    0xDEADDEADu

#define METHOD_GET  1

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

/* Write the fixed request: OPERATOR GET /status, rate=5, size=100 */
static void write_fixed_request(uint8_t *buf)
{
    write_u32(buf, 29, HASH_STATUS);     /* req_path_hash */
    buf[33] = METHOD_GET;                 /* req_method */
    buf[34] = ROLE_OPERATOR;              /* req_auth_state */
    buf[35] = 5;                          /* req_rate_count */
    write_u32(buf, 36, 100);             /* req_content_length */
    buf[40] = 0; buf[41] = 0; buf[42] = 0; /* check bytes */
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

    printf("=== Experiment 3: Dynamic Policy Update ===\n\n");
    printf("Same validator, same request (OPERATOR GET /status), different policies.\n\n");

    /*
     * Policy A (restrictive): GET /status requires ADMIN
     * OPERATOR < ADMIN → REJECT
     */
    memset(buf, 0, BUF_SIZE);
    buf[0] = 10;                        /* max_rate */
    write_u32(buf, 1, 4096);            /* max_body */
    write_rule(buf,  5, HASH_STATUS, METHOD_GET, ROLE_ADMIN);  /* min_role=ADMIN */
    write_rule(buf, 11, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 17, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 23, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_fixed_request(buf);
    total++; passed += run_test("Policy A (restrictive): min_role=ADMIN → REJECT", buf, BUF_SIZE, 0);

    /*
     * Policy B (permissive): GET /status requires OPERATOR
     * OPERATOR >= OPERATOR → ACCEPT
     */
    memset(buf, 0, BUF_SIZE);
    buf[0] = 10;
    write_u32(buf, 1, 4096);
    write_rule(buf,  5, HASH_STATUS, METHOD_GET, ROLE_OPERATOR);  /* min_role=OPERATOR */
    write_rule(buf, 11, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 17, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 23, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_fixed_request(buf);
    total++; passed += run_test("Policy B (permissive): min_role=OPERATOR → ACCEPT", buf, BUF_SIZE, 1);

    /*
     * Policy C (lockdown): all rules use DEAD_HASH (no request can match)
     * Deny-by-default → REJECT
     */
    memset(buf, 0, BUF_SIZE);
    buf[0] = 10;
    write_u32(buf, 1, 4096);
    write_rule(buf,  5, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 11, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 17, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_rule(buf, 23, DEAD_HASH, METHOD_GET, ROLE_NONE);
    write_fixed_request(buf);
    total++; passed += run_test("Policy C (lockdown): all DEAD_HASH → REJECT", buf, BUF_SIZE, 0);

    printf("\nResults: %d/%d passed\n", passed, total);
    printf("\nConclusion: Same verified validator binary, different policy data,\n");
    printf("different access decisions. Policy is DATA, enforcement is VERIFIED CODE.\n");
    return (passed == total) ? 0 : 1;
}
