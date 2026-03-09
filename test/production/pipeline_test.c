/*
 * Batch C: Multi-Session E2E Pipeline — Test Harness
 *
 * 8 scenarios, 46 tests total:
 *   C1. Session Isolation                    — 8 tests
 *   C2. Session Table Exhaustion             — 4 tests
 *   C3. Extractor Rejection                  — 3 tests
 *   C4. E2E RBAC Lifecycle                   — 6 tests
 *   C5. Interleaved Multi-Client             — 11 tests
 *   C6. Direct State Manipulation            — 1 test (adversarial)
 *   C7. Scope Bitfield Enforcement           — 8 tests (Phase 5)
 *   C8. Rate Exhaustion                      — 5 tests
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "pipeline.h"
#include "generated/RbacPolicyWrapper.h"

static int total_passed = 0;
static int total_tests = 0;

/* Helper: check step result and role */
static int check_step(const char *desc,
                      RequestResult actual, RequestResult expected,
                      uint8_t actual_role, uint8_t expected_role)
{
    total_tests++;
    int result_ok = (actual == expected);
    int role_ok = (actual_role == expected_role);
    int passed = result_ok && role_ok;

    if (passed) {
        total_passed++;
        printf("    PASS: %s\n", desc);
        printf("          result=%s, role=%s\n",
               result_name(actual), role_name(actual_role));
    } else {
        printf("    FAIL: %s\n", desc);
        printf("          expected result=%s role=%s\n",
               result_name(expected), role_name(expected_role));
        printf("          got      result=%s role=%s\n",
               result_name(actual), role_name(actual_role));
    }
    return passed;
}

/*
 * Helper: build login body
 * Format: [username_len:1][username:N][password_len:1][password:M]
 */
static uint32_t build_login_body(uint8_t *body,
                                 const char *username,
                                 const char *password)
{
    uint8_t ulen = (uint8_t)strlen(username);
    uint8_t plen = (uint8_t)strlen(password);
    uint32_t pos = 0;
    body[pos++] = ulen;
    memcpy(body + pos, username, ulen);
    pos += ulen;
    body[pos++] = plen;
    memcpy(body + pos, password, plen);
    pos += plen;
    return pos;
}

/* Helper: write a u32 in little-endian */
static void test_write_u32(uint8_t *buf, int offset, uint32_t val)
{
    buf[offset + 0] = (val >>  0) & 0xFF;
    buf[offset + 1] = (val >>  8) & 0xFF;
    buf[offset + 2] = (val >> 16) & 0xFF;
    buf[offset + 3] = (val >> 24) & 0xFF;
}

/* Helper: write a u16 in little-endian */
static void test_write_u16(uint8_t *buf, int offset, uint16_t val)
{
    buf[offset + 0] = (val >> 0) & 0xFF;
    buf[offset + 1] = (val >> 8) & 0xFF;
}

/*
 * Helper: build policy update body
 * Format: [num_rules:1][rule_0:8]...[rule_7:8] = 65 bytes
 */
static uint32_t build_policy_body(uint8_t *body, uint8_t num_rules,
                                  const PolicyRule rules[MAX_RULES])
{
    body[0] = num_rules;
    for (int i = 0; i < MAX_RULES; i++) {
        int off = 1 + i * 8;
        test_write_u32(body, off, rules[i].path_hash);
        body[off + 4] = rules[i].method;
        body[off + 5] = rules[i].min_role;
        test_write_u16(body, off + 6, rules[i].req_scope);
    }
    return 65; /* 1 + 8*8 */
}

/* Helper: build a MockHTTPRequest */
static MockHTTPRequest make_req(uint32_t path_hash, uint8_t method,
                                const uint8_t *body, uint32_t body_len)
{
    MockHTTPRequest r;
    r.path_hash = path_hash;
    r.method = method;
    r.content_length = body_len;
    r.body = body;
    r.body_len = body_len;
    return r;
}

/* Helper: get auth_state for a client, or ROLE_NONE if not found */
static uint8_t get_role(SessionTable *sessions, uint32_t client_id)
{
    SessionEntry *se = session_lookup(sessions, client_id);
    if (se) return se->auth_state;
    return ROLE_NONE;
}

/* ============================================================ */

/*
 * Scenario C1: Session Isolation (8 tests)
 * Two clients, independent auth state.
 */
static void scenario_c1(void)
{
    SessionTable sessions;
    Policy policy;
    session_table_init(&sessions);
    policy_init_default(&policy);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;
    MockHTTPRequest req;

    printf("=== Scenario C1: Session Isolation ===\n");

    /* 1. Client A(0xAA) POST /login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0xAA, &req);
    check_step("C1.1: Client A POST /login as admin",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0xAA), ROLE_ADMIN);

    /* 2. Client B(0xBB) GET /status -> DENIED (B=NONE, independent) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xBB, &req);
    check_step("C1.2: Client B GET /status (NONE -> DENIED)",
               r, RESULT_DENIED, get_role(&sessions, 0xBB), ROLE_NONE);

    /* 3. Client A GET /status -> STATUS_OK */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xAA, &req);
    check_step("C1.3: Client A GET /status (ADMIN -> OK)",
               r, RESULT_STATUS_OK, get_role(&sessions, 0xAA), ROLE_ADMIN);

    /* 4. Client B POST /login as operator */
    body_len = build_login_body(body, "operator", "oper123");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0xBB, &req);
    check_step("C1.4: Client B POST /login as operator",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0xBB), ROLE_OPERATOR);

    /* 5. Client B GET /status -> STATUS_OK */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xBB, &req);
    check_step("C1.5: Client B GET /status (OPERATOR -> OK)",
               r, RESULT_STATUS_OK, get_role(&sessions, 0xBB), ROLE_OPERATOR);

    /* 6. Client A POST /logout */
    req = make_req(PATH_LOGOUT, METHOD_POST, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xAA, &req);
    check_step("C1.6: Client A POST /logout",
               r, RESULT_LOGOUT_SUCCESS, get_role(&sessions, 0xAA), ROLE_NONE);

    /* 7. Client A GET /status -> DENIED (logged out) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xAA, &req);
    check_step("C1.7: Client A GET /status (logged out -> DENIED)",
               r, RESULT_DENIED, get_role(&sessions, 0xAA), ROLE_NONE);

    /* 8. Client B GET /status -> STATUS_OK (unaffected by A's logout) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xBB, &req);
    check_step("C1.8: Client B GET /status (unaffected by A logout)",
               r, RESULT_STATUS_OK, get_role(&sessions, 0xBB), ROLE_OPERATOR);

    printf("\n");
}

/*
 * Scenario C2: Session Table Exhaustion (4 tests)
 */
static void scenario_c2(void)
{
    SessionTable sessions;
    Policy policy;
    session_table_init(&sessions);
    policy_init_default(&policy);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;
    MockHTTPRequest req;

    printf("=== Scenario C2: Session Table Exhaustion ===\n");

    /* 1. Create 8 clients (id=1..8), each POST /login as operator */
    int all_ok = 1;
    for (uint32_t cid = 1; cid <= 8; cid++) {
        body_len = build_login_body(body, "operator", "oper123");
        req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
        r = pipeline_process(&sessions, &policy, cid, &req);
        if (r != RESULT_LOGIN_SUCCESS || get_role(&sessions, cid) != ROLE_OPERATOR) {
            all_ok = 0;
        }
    }
    total_tests++;
    if (all_ok) {
        total_passed++;
        printf("    PASS: C2.1: 8 clients login as operator (all LOGIN_SUCCESS)\n");
        printf("          active_sessions=%d\n", session_count_active(&sessions));
    } else {
        printf("    FAIL: C2.1: Not all 8 clients logged in successfully\n");
    }

    /* 2. Client 9 POST /login -> RESULT_NO_SESSION */
    body_len = build_login_body(body, "operator", "oper123");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 9, &req);
    check_step("C2.2: Client 9 POST /login (table full -> NO_SESSION)",
               r, RESULT_NO_SESSION, ROLE_NONE, ROLE_NONE);

    /* 3. Destroy client 1, then client 9 can login */
    session_destroy(&sessions, 1);
    body_len = build_login_body(body, "operator", "oper123");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 9, &req);
    check_step("C2.3: Client 9 POST /login (after destroy -> LOGIN_SUCCESS)",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 9), ROLE_OPERATOR);

    /* 4. Verify active count == 8 */
    int active = session_count_active(&sessions);
    total_tests++;
    if (active == 8) {
        total_passed++;
        printf("    PASS: C2.4: active_sessions=%d (expected 8)\n", active);
    } else {
        printf("    FAIL: C2.4: active_sessions=%d (expected 8)\n", active);
    }

    printf("\n");
}

/*
 * Scenario C3: Extractor Rejection (3 tests)
 */
static void scenario_c3(void)
{
    SessionTable sessions;
    Policy policy;
    session_table_init(&sessions);
    policy_init_default(&policy);
    RequestResult r;
    MockHTTPRequest req;

    printf("=== Scenario C3: Extractor Rejection ===\n");

    /* 1. content_length=100000 (exceeds 65536) -> EXTRACTION_FAILED */
    req.path_hash = PATH_STATUS;
    req.method = METHOD_GET;
    req.content_length = 100000;
    req.body = NULL;
    req.body_len = 0;
    r = pipeline_process(&sessions, &policy, 0xF1, &req);
    check_step("C3.1: content_length=100000 -> EXTRACTION_FAILED",
               r, RESULT_EXTRACTION_FAILED, get_role(&sessions, 0xF1), ROLE_NONE);

    /* 2. method=0 (invalid) -> EXTRACTION_FAILED */
    req.path_hash = PATH_STATUS;
    req.method = 0;
    req.content_length = 0;
    req.body = NULL;
    req.body_len = 0;
    r = pipeline_process(&sessions, &policy, 0xF2, &req);
    check_step("C3.2: method=0 (invalid) -> EXTRACTION_FAILED",
               r, RESULT_EXTRACTION_FAILED, get_role(&sessions, 0xF2), ROLE_NONE);

    /* 3. Normal GET /status, content_length=100 -> proceeds to EverParse
     *    (DENIED since not logged in, but extraction passes) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    req.content_length = 100;
    r = pipeline_process(&sessions, &policy, 0xF3, &req);
    check_step("C3.3: normal GET /status (extraction OK, EverParse DENIED)",
               r, RESULT_DENIED, get_role(&sessions, 0xF3), ROLE_NONE);

    printf("\n");
}

/*
 * Scenario C4: E2E RBAC Lifecycle (6 tests)
 * Full lifecycle through the pipeline (mirrors Batch A Scenario 2).
 */
static void scenario_c4(void)
{
    SessionTable sessions;
    Policy policy;
    session_table_init(&sessions);
    policy_init_default(&policy);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;
    MockHTTPRequest req;

    printf("=== Scenario C4: E2E RBAC Lifecycle ===\n");

    /* 1. Client 0xDD POST /login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0xDD, &req);
    check_step("C4.1: Client 0xDD POST /login as admin",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0xDD), ROLE_ADMIN);

    /* 2. Client 0xDD GET /status -> STATUS_OK */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xDD, &req);
    check_step("C4.2: Client 0xDD GET /status",
               r, RESULT_STATUS_OK, get_role(&sessions, 0xDD), ROLE_ADMIN);

    /* 3. Client 0xDD PUT /policy (status -> ADMIN-only) */
    PolicyRule new_rules[MAX_RULES] = {
        { PATH_STATUS, METHOD_GET,  ROLE_ADMIN,    0 },    /* was OPERATOR */
        { PATH_LOGOUT, METHOD_POST, ROLE_OPERATOR, 0 },
        { PATH_POLICY, METHOD_GET,  ROLE_ADMIN,    0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
    };
    body_len = build_policy_body(body, 3, new_rules);
    req = make_req(PATH_POLICY, METHOD_PUT, body, body_len);
    r = pipeline_process(&sessions, &policy, 0xDD, &req);
    check_step("C4.3: Client 0xDD PUT /policy (status->ADMIN-only)",
               r, RESULT_POLICY_UPDATED, get_role(&sessions, 0xDD), ROLE_ADMIN);

    /* 4. Client 0xDD POST /logout */
    req = make_req(PATH_LOGOUT, METHOD_POST, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xDD, &req);
    check_step("C4.4: Client 0xDD POST /logout",
               r, RESULT_LOGOUT_SUCCESS, get_role(&sessions, 0xDD), ROLE_NONE);

    /* 5. Client 0xEE POST /login as operator */
    body_len = build_login_body(body, "operator", "oper123");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0xEE, &req);
    check_step("C4.5: Client 0xEE POST /login as operator",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0xEE), ROLE_OPERATOR);

    /* 6. Client 0xEE GET /status -> DENIED (new policy requires ADMIN) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xEE, &req);
    check_step("C4.6: Client 0xEE GET /status (ADMIN required -> DENIED)",
               r, RESULT_DENIED, get_role(&sessions, 0xEE), ROLE_OPERATOR);

    printf("\n");
}

/*
 * Scenario C5: Interleaved Multi-Client (11 tests)
 * Three clients, interleaved ops, policy change affects all.
 */
static void scenario_c5(void)
{
    SessionTable sessions;
    Policy policy;
    session_table_init(&sessions);
    policy_init_default(&policy);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;
    MockHTTPRequest req;

    printf("=== Scenario C5: Interleaved Multi-Client ===\n");

    /* 1. Client A(0x10) POST /login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0x10, &req);
    check_step("C5.1: Client A POST /login as admin",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0x10), ROLE_ADMIN);

    /* 2. Client B(0x20) POST /login as operator */
    body_len = build_login_body(body, "operator", "oper123");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0x20, &req);
    check_step("C5.2: Client B POST /login as operator",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0x20), ROLE_OPERATOR);

    /* 3. Client C(0x30) GET /status -> DENIED (never logged in) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0x30, &req);
    check_step("C5.3: Client C GET /status (never logged in -> DENIED)",
               r, RESULT_DENIED, get_role(&sessions, 0x30), ROLE_NONE);

    /* 4. Client A PUT /policy (/status -> ADMIN-only) */
    PolicyRule new_rules[MAX_RULES] = {
        { PATH_STATUS, METHOD_GET,  ROLE_ADMIN,    0 },
        { PATH_LOGOUT, METHOD_POST, ROLE_OPERATOR, 0 },
        { PATH_POLICY, METHOD_GET,  ROLE_ADMIN,    0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
    };
    body_len = build_policy_body(body, 3, new_rules);
    req = make_req(PATH_POLICY, METHOD_PUT, body, body_len);
    r = pipeline_process(&sessions, &policy, 0x10, &req);
    check_step("C5.4: Client A PUT /policy (status->ADMIN-only)",
               r, RESULT_POLICY_UPDATED, get_role(&sessions, 0x10), ROLE_ADMIN);

    /* 5. Client B GET /status -> DENIED (policy changed) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0x20, &req);
    check_step("C5.5: Client B GET /status (policy changed -> DENIED)",
               r, RESULT_DENIED, get_role(&sessions, 0x20), ROLE_OPERATOR);

    /* 6. Client A GET /status -> STATUS_OK (admin) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0x10, &req);
    check_step("C5.6: Client A GET /status (ADMIN -> OK)",
               r, RESULT_STATUS_OK, get_role(&sessions, 0x10), ROLE_ADMIN);

    /* 7. Client C POST /login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0x30, &req);
    check_step("C5.7: Client C POST /login as admin",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0x30), ROLE_ADMIN);

    /* 8. Client C GET /status -> STATUS_OK */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0x30, &req);
    check_step("C5.8: Client C GET /status (ADMIN -> OK)",
               r, RESULT_STATUS_OK, get_role(&sessions, 0x30), ROLE_ADMIN);

    /* 9. Client A POST /logout */
    req = make_req(PATH_LOGOUT, METHOD_POST, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0x10, &req);
    check_step("C5.9: Client A POST /logout",
               r, RESULT_LOGOUT_SUCCESS, get_role(&sessions, 0x10), ROLE_NONE);

    /* 10. Client A GET /status -> DENIED (logged out) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0x10, &req);
    check_step("C5.10: Client A GET /status (logged out -> DENIED)",
               r, RESULT_DENIED, get_role(&sessions, 0x10), ROLE_NONE);

    /* 11. Client C GET /status -> STATUS_OK (unaffected) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0x30, &req);
    check_step("C5.11: Client C GET /status (unaffected -> OK)",
               r, RESULT_STATUS_OK, get_role(&sessions, 0x30), ROLE_ADMIN);

    printf("\n");
}

/*
 * Scenario C6: Direct State Manipulation — Adversarial Sanity Check (1 test)
 *
 * Manually set auth_state=ADMIN on a session without logging in,
 * then call GET /status. This validates the trust model: the glue code
 * populates the EverParse buffer from session state, so if session state
 * is corrupted, the validator will accept.
 */
static void scenario_c6(void)
{
    SessionTable sessions;
    Policy policy;
    session_table_init(&sessions);
    policy_init_default(&policy);
    RequestResult r;
    MockHTTPRequest req;

    printf("=== Scenario C6: Direct State Manipulation (Adversarial) ===\n");

    /* Step 1: Create session for client 99 WITHOUT logging in */
    SessionEntry *se = session_create(&sessions, 99);

    /* Step 2: Manually set auth_state to ADMIN (bypassing login) */
    se->auth_state = ROLE_ADMIN;
    printf("    INFO: Manually set client_id=99 auth_state=ADMIN (no login)\n");

    /* Step 3: GET /status — should succeed because glue code reads
     * auth_state from session and writes it into the EverParse buffer.
     * EverParse checks auth_state >= min_role from the buffer, not
     * from any login proof. This confirms the trust model: the glue
     * code (buffer construction) IS the trust boundary. */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 99, &req);
    check_step("C6.1: GET /status with manually-set ADMIN (trust model test)",
               r, RESULT_STATUS_OK, get_role(&sessions, 99), ROLE_ADMIN);

    printf("    NOTE: PASS = expected. The glue code is the trust boundary.\n");
    printf("          EverParse verifies the buffer, not how the buffer was built.\n");
    printf("          In production, the glue code runs in a verified CAmkES component.\n");

    printf("\n");
}

/*
 * Scenario C7: Scope Bitfield Enforcement (8 tests, Phase 5)
 *
 * Tests the 4th conjunct: (auth_scope & req_scope) == req_scope
 * Scope bits: READ_SENSORS=0x01, WRITE_SENSORS=0x02, CONFIGURE=0x04
 * Operator scope=0x03 (READ|WRITE), Admin scope=0x3F (all 6 bits)
 *
 * Uses a fresh policy with scope requirements on rules.
 * Directly manipulates session auth_state + uses a custom pipeline_process
 * variant that injects auth_scope into the AccessRequest buffer.
 *
 * Since standalone pipeline.c hardcodes auth_scope=0xFFFF, we test scope
 * by uploading a policy with scope requirements and verifying via direct
 * EverParse buffer construction.
 */
static void scenario_c7(void)
{
    printf("=== Scenario C7: Scope Bitfield Enforcement (Phase 5) ===\n");

    /*
     * Direct EverParse buffer tests — bypasses pipeline_process to control
     * auth_scope precisely. This tests the verified validator in isolation.
     *
     * AccessRequest layout (75 bytes):
     *   [auth_state:1][rate_count:1][auth_scope:2]
     *   [rule_0:8]...[rule_7:8]  (64 bytes)
     *   [req_path_hash:4][req_method:1]
     *   [_rate_ok:1][_access_ok:1]
     */
    #define SCOPE_ACCESS_REQ_SIZE 75

    /* Helper for building scope test buffers inline */
    #define SCOPE_READ_SENSORS  0x01
    #define SCOPE_WRITE_SENSORS 0x02
    #define SCOPE_CONFIGURE     0x04

    /* Policy: rule 0 = GET /status, OPERATOR, requires READ_SENSORS(0x01) */
    /* All other rules are dead */

    uint8_t buf[SCOPE_ACCESS_REQ_SIZE];
    BOOLEAN accepted;

    /* Shared rule data: rule 0 requires OPERATOR + READ_SENSORS */
    PolicyRule scope_rules[MAX_RULES] = {
        { PATH_STATUS, METHOD_GET, ROLE_OPERATOR, SCOPE_READ_SENSORS },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
        { DEAD_HASH, 0, 0, 0 },
    };

    /* -- Helper: build AccessRequest buffer -- */
    #define BUILD_SCOPE_BUF(auth_st, scope_val, path, meth) do { \
        memset(buf, 0, SCOPE_ACCESS_REQ_SIZE); \
        buf[0] = (auth_st); \
        buf[1] = 0; /* rate_count */ \
        buf[2] = (uint8_t)((scope_val) & 0xFF); \
        buf[3] = (uint8_t)(((scope_val) >> 8) & 0xFF); \
        for (int _i = 0; _i < MAX_RULES; _i++) { \
            int _off = 4 + _i * 8; \
            buf[_off+0] = (uint8_t)((scope_rules[_i].path_hash >>  0) & 0xFF); \
            buf[_off+1] = (uint8_t)((scope_rules[_i].path_hash >>  8) & 0xFF); \
            buf[_off+2] = (uint8_t)((scope_rules[_i].path_hash >> 16) & 0xFF); \
            buf[_off+3] = (uint8_t)((scope_rules[_i].path_hash >> 24) & 0xFF); \
            buf[_off+4] = scope_rules[_i].method; \
            buf[_off+5] = scope_rules[_i].min_role; \
            buf[_off+6] = (uint8_t)((scope_rules[_i].req_scope >> 0) & 0xFF); \
            buf[_off+7] = (uint8_t)((scope_rules[_i].req_scope >> 8) & 0xFF); \
        } \
        int _roff = 4 + 64; /* offset 68 */ \
        buf[_roff+0] = (uint8_t)(((path) >>  0) & 0xFF); \
        buf[_roff+1] = (uint8_t)(((path) >>  8) & 0xFF); \
        buf[_roff+2] = (uint8_t)(((path) >> 16) & 0xFF); \
        buf[_roff+3] = (uint8_t)(((path) >> 24) & 0xFF); \
        buf[_roff+4] = (meth); \
    } while(0)

    /* C7.1: Admin(0x3F) + rule requires READ_SENSORS(0x01) -> ACCEPT */
    BUILD_SCOPE_BUF(ROLE_ADMIN, 0x3F, PATH_STATUS, METHOD_GET);
    accepted = RbacPolicyCheckAccessRequest(buf, SCOPE_ACCESS_REQ_SIZE);
    total_tests++;
    if (accepted) { total_passed++; printf("    PASS: C7.1: Admin(0x3F) scope covers READ_SENSORS(0x01) -> ACCEPT\n"); }
    else { printf("    FAIL: C7.1: Admin(0x3F) scope covers READ_SENSORS(0x01) -> expected ACCEPT got DENY\n"); }

    /* C7.2: Operator(0x03) + rule requires READ_SENSORS(0x01) -> ACCEPT */
    BUILD_SCOPE_BUF(ROLE_OPERATOR, 0x03, PATH_STATUS, METHOD_GET);
    accepted = RbacPolicyCheckAccessRequest(buf, SCOPE_ACCESS_REQ_SIZE);
    total_tests++;
    if (accepted) { total_passed++; printf("    PASS: C7.2: Operator(0x03) scope covers READ_SENSORS(0x01) -> ACCEPT\n"); }
    else { printf("    FAIL: C7.2: Operator(0x03) scope covers READ_SENSORS(0x01) -> expected ACCEPT got DENY\n"); }

    /* C7.3: Operator(0x03) + rule requires CONFIGURE(0x04) -> DENY */
    scope_rules[0].req_scope = SCOPE_CONFIGURE;
    BUILD_SCOPE_BUF(ROLE_OPERATOR, 0x03, PATH_STATUS, METHOD_GET);
    accepted = RbacPolicyCheckAccessRequest(buf, SCOPE_ACCESS_REQ_SIZE);
    total_tests++;
    if (!accepted) { total_passed++; printf("    PASS: C7.3: Operator(0x03) missing CONFIGURE(0x04) -> DENY\n"); }
    else { printf("    FAIL: C7.3: Operator(0x03) missing CONFIGURE(0x04) -> expected DENY got ACCEPT\n"); }

    /* C7.4: Admin(0x3F) + rule requires no scope(0x00) -> ACCEPT */
    scope_rules[0].req_scope = 0x0000;
    BUILD_SCOPE_BUF(ROLE_ADMIN, 0x3F, PATH_STATUS, METHOD_GET);
    accepted = RbacPolicyCheckAccessRequest(buf, SCOPE_ACCESS_REQ_SIZE);
    total_tests++;
    if (accepted) { total_passed++; printf("    PASS: C7.4: Admin(0x3F) + no scope required(0x00) -> ACCEPT\n"); }
    else { printf("    FAIL: C7.4: Admin(0x3F) + no scope required(0x00) -> expected ACCEPT got DENY\n"); }

    /* C7.5: NONE(0x00 scope) + rule requires READ_SENSORS(0x01) -> DENY (role fails) */
    scope_rules[0].req_scope = SCOPE_READ_SENSORS;
    BUILD_SCOPE_BUF(ROLE_NONE, 0x00, PATH_STATUS, METHOD_GET);
    accepted = RbacPolicyCheckAccessRequest(buf, SCOPE_ACCESS_REQ_SIZE);
    total_tests++;
    if (!accepted) { total_passed++; printf("    PASS: C7.5: NONE role + scope 0x00 -> DENY (role insufficient)\n"); }
    else { printf("    FAIL: C7.5: NONE role + scope 0x00 -> expected DENY got ACCEPT\n"); }

    /* C7.6: Dead rule with scope=0xFF still DENY (path_match fails first) */
    scope_rules[0] = (PolicyRule){ DEAD_HASH, 0, 0, 0xFF };
    BUILD_SCOPE_BUF(ROLE_ADMIN, 0xFFFF, PATH_STATUS, METHOD_GET);
    accepted = RbacPolicyCheckAccessRequest(buf, SCOPE_ACCESS_REQ_SIZE);
    total_tests++;
    if (!accepted) { total_passed++; printf("    PASS: C7.6: Dead rule with scope=0xFF -> DENY (path mismatch)\n"); }
    else { printf("    FAIL: C7.6: Dead rule with scope=0xFF -> expected DENY got ACCEPT\n"); }

    /* C7.7: Operator(0x03) + rule requires READ|WRITE(0x03) -> ACCEPT */
    scope_rules[0] = (PolicyRule){ PATH_STATUS, METHOD_GET, ROLE_OPERATOR,
                                   SCOPE_READ_SENSORS | SCOPE_WRITE_SENSORS };
    BUILD_SCOPE_BUF(ROLE_OPERATOR, 0x03, PATH_STATUS, METHOD_GET);
    accepted = RbacPolicyCheckAccessRequest(buf, SCOPE_ACCESS_REQ_SIZE);
    total_tests++;
    if (accepted) { total_passed++; printf("    PASS: C7.7: Operator(0x03) scope matches READ|WRITE(0x03) -> ACCEPT\n"); }
    else { printf("    FAIL: C7.7: Operator(0x03) scope matches READ|WRITE(0x03) -> expected ACCEPT got DENY\n"); }

    /* C7.8: Operator(0x03) + rule requires READ|WRITE|CONFIGURE(0x07) -> DENY */
    scope_rules[0] = (PolicyRule){ PATH_STATUS, METHOD_GET, ROLE_OPERATOR,
                                   SCOPE_READ_SENSORS | SCOPE_WRITE_SENSORS | SCOPE_CONFIGURE };
    BUILD_SCOPE_BUF(ROLE_OPERATOR, 0x03, PATH_STATUS, METHOD_GET);
    accepted = RbacPolicyCheckAccessRequest(buf, SCOPE_ACCESS_REQ_SIZE);
    total_tests++;
    if (!accepted) { total_passed++; printf("    PASS: C7.8: Operator(0x03) missing CONFIGURE in 0x07 -> DENY\n"); }
    else { printf("    FAIL: C7.8: Operator(0x03) missing CONFIGURE in 0x07 -> expected DENY got ACCEPT\n"); }

    #undef BUILD_SCOPE_BUF
    #undef SCOPE_ACCESS_REQ_SIZE
    #undef SCOPE_READ_SENSORS
    #undef SCOPE_WRITE_SENSORS
    #undef SCOPE_CONFIGURE

    printf("\n");
}

/*
 * Scenario C8: Rate Exhaustion (5 tests)
 *
 * Tests rate_count field in EverParse buffer.
 * The standalone pipeline.c increments rate_count per request via session.
 * After 50 requests, EverParse should reject (rate_count >= MAX_RATE).
 *
 * This exercises the same EverParse rate constraint as the CAmkES RateLimiter,
 * but uses the standalone session-based rate counter.
 */
static void scenario_c8(void)
{
    SessionTable sessions;
    Policy policy;
    session_table_init(&sessions);
    policy_init_default(&policy);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;
    MockHTTPRequest req;

    printf("=== Scenario C8: Rate Exhaustion ===\n");

    /* 1. Login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0xCC, &req);
    check_step("C8.1: Login as admin",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0xCC), ROLE_ADMIN);

    /* 2. Send 48 more GET /status requests (login was #1, so we need 48 more to reach 49) */
    int all_ok = 1;
    for (int i = 0; i < 48; i++) {
        req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
        r = pipeline_process(&sessions, &policy, 0xCC, &req);
        if (r != RESULT_STATUS_OK) {
            all_ok = 0;
            printf("    FAIL: Request %d unexpectedly denied\n", i + 2);
            break;
        }
    }
    total_tests++;
    if (all_ok) {
        total_passed++;
        printf("    PASS: C8.2: 48 more GET /status all OK (rate_count=49)\n");
    } else {
        printf("    FAIL: C8.2: Some requests denied before rate limit\n");
    }

    /* 3. Request #50 -> should still pass (rate_count=49 at check time, incremented to 50 after) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xCC, &req);
    check_step("C8.3: Request #50 (rate_count=49 at check -> OK)",
               r, RESULT_STATUS_OK, get_role(&sessions, 0xCC), ROLE_ADMIN);

    /* 4. Request #51 -> DENIED (rate_count=50 >= MAX_RATE at EverParse check) */
    req = make_req(PATH_STATUS, METHOD_GET, NULL, 0);
    r = pipeline_process(&sessions, &policy, 0xCC, &req);
    check_step("C8.4: Request #51 (rate_count=50 >= MAX_RATE -> DENIED)",
               r, RESULT_DENIED, get_role(&sessions, 0xCC), ROLE_ADMIN);

    /* 5. Login from a different client -> still works (independent rate counter) */
    body_len = build_login_body(body, "admin", "admin456");
    req = make_req(PATH_LOGIN, METHOD_POST, body, body_len);
    r = pipeline_process(&sessions, &policy, 0xDD, &req);
    check_step("C8.5: Different client login (independent rate -> OK)",
               r, RESULT_LOGIN_SUCCESS, get_role(&sessions, 0xDD), ROLE_ADMIN);

    printf("\n");
}

/* ============================================================ */

int main(void)
{
    printf("Batch C: Multi-Session E2E Pipeline Simulation\n");
    printf("===============================================\n\n");

    scenario_c1();
    scenario_c2();
    scenario_c3();
    scenario_c4();
    scenario_c5();
    scenario_c6();
    scenario_c7();
    scenario_c8();

    printf("===============================================\n");
    printf("Results: %d/%d tests passed\n", total_passed, total_tests);

    if (total_passed == total_tests) {
        printf("\nAll scenarios passed. Multi-session pipeline confirmed:\n");
        printf("  - Session isolation: independent auth state per client\n");
        printf("  - Bounded sessions: table exhaustion returns NO_SESSION\n");
        printf("  - Defense in depth: extractor rejects before EverParse\n");
        printf("  - E2E RBAC: login -> policy update -> enforcement\n");
        printf("  - Shared policy, isolated sessions: policy change affects all\n");
        printf("  - Scope bitfield: (auth_scope & req_scope) == req_scope enforced\n");
        printf("  - Rate limiting: EverParse denies after MAX_RATE requests\n");
    }

    /* ---- Validator latency benchmark ---- */
    if (total_passed == total_tests) {
        printf("\n=== Validator Latency Benchmark ===\n");

        /* Build a valid AccessRequest buffer (ADMIN, rate_count=0,
         * scope=0xFFFF, default policy, GET /status) */
        Policy bench_policy;
        policy_init_default(&bench_policy);

        #define BENCH_ACCESS_REQ_SIZE 75
        uint8_t bench_buf[BENCH_ACCESS_REQ_SIZE];
        memset(bench_buf, 0, BENCH_ACCESS_REQ_SIZE);
        bench_buf[0] = ROLE_ADMIN;      /* auth_state */
        bench_buf[1] = 0;               /* rate_count */
        bench_buf[2] = 0xFF;            /* auth_scope lo */
        bench_buf[3] = 0xFF;            /* auth_scope hi */
        /* Write rules at offset 4 */
        for (int i = 0; i < MAX_RULES; i++) {
            int off = 4 + i * 8;
            uint32_t ph = bench_policy.rules[i].path_hash;
            bench_buf[off+0] = (uint8_t)((ph >>  0) & 0xFF);
            bench_buf[off+1] = (uint8_t)((ph >>  8) & 0xFF);
            bench_buf[off+2] = (uint8_t)((ph >> 16) & 0xFF);
            bench_buf[off+3] = (uint8_t)((ph >> 24) & 0xFF);
            bench_buf[off+4] = bench_policy.rules[i].method;
            bench_buf[off+5] = bench_policy.rules[i].min_role;
            uint16_t rs = bench_policy.rules[i].req_scope;
            bench_buf[off+6] = (uint8_t)(rs & 0xFF);
            bench_buf[off+7] = (uint8_t)((rs >> 8) & 0xFF);
        }
        /* req_path_hash = PATH_STATUS at offset 68 */
        uint32_t rph = PATH_STATUS;
        bench_buf[68] = (uint8_t)((rph >>  0) & 0xFF);
        bench_buf[69] = (uint8_t)((rph >>  8) & 0xFF);
        bench_buf[70] = (uint8_t)((rph >> 16) & 0xFF);
        bench_buf[71] = (uint8_t)((rph >> 24) & 0xFF);
        bench_buf[72] = METHOD_GET;

        /* Sanity: verify the buffer is accepted */
        BOOLEAN sanity = RbacPolicyCheckAccessRequest(bench_buf, BENCH_ACCESS_REQ_SIZE);
        printf("  Sanity check: %s\n", sanity ? "ACCEPT (good)" : "DENY (ERROR)");

        /* Benchmark: 1M iterations */
        #define BENCH_ITERATIONS 1000000
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < BENCH_ITERATIONS; i++) {
            (void)RbacPolicyCheckAccessRequest(bench_buf, BENCH_ACCESS_REQ_SIZE);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        uint64_t ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                    + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
        printf("  Iterations: %d\n", BENCH_ITERATIONS);
        printf("  Total time: %lu ns\n", (unsigned long)ns);
        printf("  Validator latency: %lu ns/call\n", (unsigned long)(ns / BENCH_ITERATIONS));
        #undef BENCH_ITERATIONS
    }

    return (total_passed == total_tests) ? 0 : 1;
}
