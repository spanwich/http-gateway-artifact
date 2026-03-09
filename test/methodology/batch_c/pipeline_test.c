/*
 * Batch C: Multi-Session E2E Pipeline — Test Harness
 *
 * 6 scenarios, 33 tests total:
 *   C1. Session Isolation                    — 8 tests
 *   C2. Session Table Exhaustion             — 4 tests
 *   C3. Extractor Rejection                  — 3 tests
 *   C4. E2E RBAC Lifecycle                   — 6 tests
 *   C5. Interleaved Multi-Client             — 11 tests
 *   C6. Direct State Manipulation            — 1 test (adversarial)
 */

#include <stdio.h>
#include <string.h>
#include "pipeline.h"

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

/*
 * Helper: build policy update body
 * Format: [num_rules:1][rule_0:6]...[rule_7:6] = 49 bytes
 */
static uint32_t build_policy_body(uint8_t *body, uint8_t num_rules,
                                  const PolicyRule rules[MAX_RULES])
{
    body[0] = num_rules;
    for (int i = 0; i < MAX_RULES; i++) {
        int off = 1 + i * 6;
        test_write_u32(body, off, rules[i].path_hash);
        body[off + 4] = rules[i].method;
        body[off + 5] = rules[i].min_role;
    }
    return 49; /* 1 + 8*6 */
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
        { PATH_STATUS, METHOD_GET,  ROLE_ADMIN },    /* was OPERATOR */
        { PATH_LOGOUT, METHOD_POST, ROLE_OPERATOR },
        { PATH_POLICY, METHOD_GET,  ROLE_ADMIN },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
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
        { PATH_STATUS, METHOD_GET,  ROLE_ADMIN },
        { PATH_LOGOUT, METHOD_POST, ROLE_OPERATOR },
        { PATH_POLICY, METHOD_GET,  ROLE_ADMIN },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
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

    printf("===============================================\n");
    printf("Results: %d/%d tests passed\n", total_passed, total_tests);

    if (total_passed == total_tests) {
        printf("\nAll scenarios passed. Multi-session pipeline confirmed:\n");
        printf("  - Session isolation: independent auth state per client\n");
        printf("  - Bounded sessions: table exhaustion returns NO_SESSION\n");
        printf("  - Defense in depth: extractor rejects before EverParse\n");
        printf("  - E2E RBAC: login -> policy update -> enforcement\n");
        printf("  - Shared policy, isolated sessions: policy change affects all\n");
    }

    return (total_passed == total_tests) ? 0 : 1;
}
