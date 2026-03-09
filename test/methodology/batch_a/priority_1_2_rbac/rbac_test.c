/*
 * RBAC Policy System — Test Harness
 *
 * 6 scenarios, 26 tests total:
 *   1. RBAC Enforcement (role hierarchy)        — 7 steps
 *   2. Policy Update Changes Access Decisions   — 6 steps
 *   3. Non-Admin Cannot Update Policy           — 2 steps
 *   4. Lockdown Policy (all rules dead)         — 4 steps
 *   5. Role Escalation Prevention               — 4 steps
 *   6. Malformed Policy Rejected                — 3 steps
 */

#include <stdio.h>
#include <string.h>
#include "rbac_app.h"

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
static void write_u32(uint8_t *buf, int offset, uint32_t val)
{
    buf[offset + 0] = (val >>  0) & 0xFF;
    buf[offset + 1] = (val >>  8) & 0xFF;
    buf[offset + 2] = (val >> 16) & 0xFF;
    buf[offset + 3] = (val >> 24) & 0xFF;
}

/*
 * Helper: build policy update body
 * Format: [num_rules:1][rule_0:6]...[rule_7:6] = 49 bytes
 *
 * rules array must have exactly MAX_RULES entries.
 */
static uint32_t build_policy_body(uint8_t *body, uint8_t num_rules,
                                  const PolicyRule rules[MAX_RULES])
{
    body[0] = num_rules;
    for (int i = 0; i < MAX_RULES; i++) {
        int off = 1 + i * 6;
        write_u32(body, off, rules[i].path_hash);
        body[off + 4] = rules[i].method;
        body[off + 5] = rules[i].min_role;
    }
    return 49; /* 1 + 8*6 */
}

/* ============================================================ */

/*
 * Scenario 1: RBAC Enforcement (Role Hierarchy)
 * 7 steps
 */
static void scenario_1(void)
{
    Session s;
    Policy p;
    session_init(&s);
    policy_init_default(&p);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;

    printf("=== Scenario 1: RBAC Enforcement (Role Hierarchy) ===\n");

    /* Step 1: POST /login as operator */
    body_len = build_login_body(body, "operator", "oper123");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login as operator",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_OPERATOR);

    /* Step 2: GET /status (OPERATOR >= OPERATOR) */
    r = process_request(&s, &p, PATH_STATUS, METHOD_GET, NULL, 0);
    check_step("GET /status (OPERATOR >= OPERATOR)",
               r, RESULT_STATUS_OK, s.auth_state, ROLE_OPERATOR);

    /* Step 3: GET /policy (OPERATOR < ADMIN) */
    r = process_request(&s, &p, PATH_POLICY, METHOD_GET, NULL, 0);
    check_step("GET /policy (OPERATOR < ADMIN -> DENIED)",
               r, RESULT_DENIED, s.auth_state, ROLE_OPERATOR);

    /* Step 4: POST /logout */
    r = process_request(&s, &p, PATH_LOGOUT, METHOD_POST, NULL, 0);
    check_step("POST /logout",
               r, RESULT_LOGOUT_SUCCESS, s.auth_state, ROLE_NONE);

    /* Step 5: POST /login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login as admin",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_ADMIN);

    /* Step 6: GET /status (ADMIN >= OPERATOR) */
    r = process_request(&s, &p, PATH_STATUS, METHOD_GET, NULL, 0);
    check_step("GET /status (ADMIN >= OPERATOR)",
               r, RESULT_STATUS_OK, s.auth_state, ROLE_ADMIN);

    /* Step 7: GET /policy (ADMIN >= ADMIN) */
    r = process_request(&s, &p, PATH_POLICY, METHOD_GET, NULL, 0);
    check_step("GET /policy (ADMIN >= ADMIN)",
               r, RESULT_POLICY_READ_OK, s.auth_state, ROLE_ADMIN);

    printf("\n");
}

/*
 * Scenario 2: Policy Update Changes Access Decisions
 * 6 steps — the critical lifecycle test
 */
static void scenario_2(void)
{
    Session s;
    Policy p;
    session_init(&s);
    policy_init_default(&p);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;

    printf("=== Scenario 2: Policy Update Changes Access Decisions ===\n");

    /* Step 1: POST /login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login as admin",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_ADMIN);

    /* Step 2: GET /status (default policy: OPERATOR required -> ADMIN passes) */
    r = process_request(&s, &p, PATH_STATUS, METHOD_GET, NULL, 0);
    check_step("GET /status (default policy, ADMIN >= OPERATOR)",
               r, RESULT_STATUS_OK, s.auth_state, ROLE_ADMIN);

    /* Step 3: PUT /policy — change GET /status to require ADMIN */
    PolicyRule new_rules[MAX_RULES] = {
        { PATH_STATUS, METHOD_GET,  ROLE_ADMIN },    /* was OPERATOR */
        { PATH_LOGOUT, METHOD_POST, ROLE_OPERATOR },  /* unchanged */
        { PATH_POLICY, METHOD_GET,  ROLE_ADMIN },     /* unchanged */
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
    };
    body_len = build_policy_body(body, 3, new_rules);
    r = process_request(&s, &p, PATH_POLICY, METHOD_PUT, body, body_len);
    check_step("PUT /policy (change /status to ADMIN-only)",
               r, RESULT_POLICY_UPDATED, s.auth_state, ROLE_ADMIN);

    /* Step 4: POST /logout */
    r = process_request(&s, &p, PATH_LOGOUT, METHOD_POST, NULL, 0);
    check_step("POST /logout",
               r, RESULT_LOGOUT_SUCCESS, s.auth_state, ROLE_NONE);

    /* Step 5: POST /login as operator */
    body_len = build_login_body(body, "operator", "oper123");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login as operator",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_OPERATOR);

    /* Step 6: GET /status (new policy: ADMIN required -> OPERATOR DENIED) */
    r = process_request(&s, &p, PATH_STATUS, METHOD_GET, NULL, 0);
    check_step("GET /status (new policy: ADMIN required -> DENIED!)",
               r, RESULT_DENIED, s.auth_state, ROLE_OPERATOR);

    printf("\n");
}

/*
 * Scenario 3: Non-Admin Cannot Update Policy
 * 2 steps
 */
static void scenario_3(void)
{
    Session s;
    Policy p;
    session_init(&s);
    policy_init_default(&p);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;

    printf("=== Scenario 3: Non-Admin Cannot Update Policy ===\n");

    /* Step 1: POST /login as operator */
    body_len = build_login_body(body, "operator", "oper123");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login as operator",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_OPERATOR);

    /* Step 2: PUT /policy (OPERATOR < ADMIN -> DENIED by EverParse) */
    PolicyRule rules[MAX_RULES] = {
        { PATH_STATUS, METHOD_GET, ROLE_NONE },
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
    };
    body_len = build_policy_body(body, 1, rules);
    r = process_request(&s, &p, PATH_POLICY, METHOD_PUT, body, body_len);
    check_step("PUT /policy (OPERATOR -> DENIED by EverParse)",
               r, RESULT_DENIED, s.auth_state, ROLE_OPERATOR);

    printf("\n");
}

/*
 * Scenario 4: Lockdown Policy (All Rules Dead)
 * 4 steps
 */
static void scenario_4(void)
{
    Session s;
    Policy p;
    session_init(&s);
    policy_init_default(&p);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;

    printf("=== Scenario 4: Lockdown Policy (All Rules Dead) ===\n");

    /* Step 1: POST /login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login as admin",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_ADMIN);

    /* Step 2: PUT /policy — all rules DEAD_HASH */
    PolicyRule dead_rules[MAX_RULES] = {
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
    };
    body_len = build_policy_body(body, 1, dead_rules);
    r = process_request(&s, &p, PATH_POLICY, METHOD_PUT, body, body_len);
    check_step("PUT /policy (all DEAD_HASH lockdown)",
               r, RESULT_POLICY_UPDATED, s.auth_state, ROLE_ADMIN);

    /* Step 3: GET /status -> DENIED (no rule matches) */
    r = process_request(&s, &p, PATH_STATUS, METHOD_GET, NULL, 0);
    check_step("GET /status (lockdown -> DENIED)",
               r, RESULT_DENIED, s.auth_state, ROLE_ADMIN);

    /* Step 4: POST /login as admin (login bypasses policy -> survives lockdown) */
    body_len = build_login_body(body, "admin", "admin456");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login survives lockdown (separate dispatch)",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_ADMIN);

    printf("\n");
}

/*
 * Scenario 5: Role Escalation Prevention
 * 4 steps
 */
static void scenario_5(void)
{
    Session s;
    Policy p;
    session_init(&s);
    policy_init_default(&p);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;

    printf("=== Scenario 5: Role Escalation Prevention ===\n");

    /* Step 1: POST /login as operator */
    body_len = build_login_body(body, "operator", "oper123");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login as operator",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_OPERATOR);

    /* Step 2: GET /status (OK for operator) */
    r = process_request(&s, &p, PATH_STATUS, METHOD_GET, NULL, 0);
    check_step("GET /status (OPERATOR allowed)",
               r, RESULT_STATUS_OK, s.auth_state, ROLE_OPERATOR);

    /* Step 3: PUT /policy (operator tries to upload) */
    PolicyRule rules[MAX_RULES] = {
        { PATH_STATUS, METHOD_GET, ROLE_NONE },
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 },
    };
    body_len = build_policy_body(body, 1, rules);
    r = process_request(&s, &p, PATH_POLICY, METHOD_PUT, body, body_len);
    check_step("PUT /policy (operator -> DENIED)",
               r, RESULT_DENIED, s.auth_state, ROLE_OPERATOR);

    /* Step 4: GET /policy (operator tries to read) */
    r = process_request(&s, &p, PATH_POLICY, METHOD_GET, NULL, 0);
    check_step("GET /policy (operator -> DENIED)",
               r, RESULT_DENIED, s.auth_state, ROLE_OPERATOR);

    printf("\n");
}

/*
 * Scenario 6: Malformed Policy Rejected
 * 3 steps
 */
static void scenario_6(void)
{
    Session s;
    Policy p;
    session_init(&s);
    policy_init_default(&p);
    RequestResult r;
    uint8_t body[128];
    uint32_t body_len;

    printf("=== Scenario 6: Malformed Policy Rejected ===\n");

    /* Step 1: POST /login as admin */
    body_len = build_login_body(body, "admin", "admin456");
    r = process_request(&s, &p, PATH_LOGIN, METHOD_POST, body, body_len);
    check_step("POST /login as admin",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, ROLE_ADMIN);

    /* Step 2: PUT /policy with num_rules = 0 (invalid: must be >= 1) */
    PolicyRule rules[MAX_RULES] = {
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
        { DEAD_HASH, 0, 0 }, { DEAD_HASH, 0, 0 },
    };
    body_len = build_policy_body(body, 0, rules); /* num_rules = 0 -> invalid */
    r = process_request(&s, &p, PATH_POLICY, METHOD_PUT, body, body_len);
    check_step("PUT /policy with num_rules=0 (malformed -> DENIED)",
               r, RESULT_DENIED, s.auth_state, ROLE_ADMIN);

    /* Step 3: GET /status (old policy still active, should work) */
    r = process_request(&s, &p, PATH_STATUS, METHOD_GET, NULL, 0);
    check_step("GET /status (old policy still active -> OK)",
               r, RESULT_STATUS_OK, s.auth_state, ROLE_ADMIN);

    printf("\n");
}

/* ============================================================ */

int main(void)
{
    printf("RBAC Policy System — EverParse Verified Access Control\n");
    printf("=====================================================\n\n");

    scenario_1();
    scenario_2();
    scenario_3();
    scenario_4();
    scenario_5();
    scenario_6();

    printf("=====================================================\n");
    printf("Results: %d/%d tests passed\n", total_passed, total_tests);

    if (total_passed == total_tests) {
        printf("\nAll scenarios passed. Verified RBAC system confirmed:\n");
        printf("  - Role hierarchy: NONE < OPERATOR < ADMIN\n");
        printf("  - Runtime policy update changes access decisions\n");
        printf("  - Policy upload is admin-only (verified by EverParse)\n");
        printf("  - Login survives lockdown (separate dispatch)\n");
        printf("  - No role escalation possible\n");
        printf("  - Malformed policy rejected, state uncorrupted\n");
    }

    return (total_passed == total_tests) ? 0 : 1;
}
