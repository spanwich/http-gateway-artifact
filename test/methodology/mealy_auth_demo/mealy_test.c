/*
 * Mealy Machine Authentication Demo — Test Harness
 *
 * Tests state-dependent access control with verified enforcement.
 * Each scenario is a sequence of requests. The harness checks both
 * the return code and session state after each step.
 *
 * Scenarios:
 *   1. Happy path: login → access → logout
 *   2. Access before login (deny-by-default)
 *   3. Bad credentials (two-layer defense)
 *   4. Logout revokes access (state regression)
 */

#include <stdio.h>
#include <string.h>
#include "mealy_app.h"

static int total_passed = 0;
static int total_tests = 0;

static int check_step(const char *desc,
                      RequestResult actual, RequestResult expected,
                      uint8_t actual_state, uint8_t expected_state)
{
    total_tests++;
    int result_ok = (actual == expected);
    int state_ok = (actual_state == expected_state);
    int passed = result_ok && state_ok;

    if (passed) {
        total_passed++;
        printf("    PASS: %s\n", desc);
        printf("          result=%s, state=%s\n",
               result_name(actual), auth_state_name(actual_state));
    } else {
        printf("    FAIL: %s\n", desc);
        printf("          expected result=%s state=%s\n",
               result_name(expected), auth_state_name(expected_state));
        printf("          got      result=%s state=%s\n",
               result_name(actual), auth_state_name(actual_state));
    }
    return passed;
}

/*
 * Scenario 1: Happy Path
 *   Login with valid creds → GET /status → Logout
 *   Demonstrates: UNAUTH → AUTH → UNAUTH transitions
 */
static void scenario_1(void)
{
    Session s;
    session_init(&s);
    RequestResult r;

    printf("=== Scenario 1: Happy Path (Login -> Access -> Logout) ===\n");

    /* Step 1: POST /login with valid credentials */
    r = process_login_request(&s, "admin", 5, "secret123", 9);
    check_step("POST /login with valid creds",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, AUTH_OK);

    /* Step 2: GET /status (now authenticated) */
    r = process_simple_request(&s, PATH_STATUS, METHOD_GET);
    check_step("GET /status (authenticated)",
               r, RESULT_STATUS_OK, s.auth_state, AUTH_OK);

    /* Step 3: POST /logout */
    r = process_simple_request(&s, PATH_LOGOUT, METHOD_POST);
    check_step("POST /logout",
               r, RESULT_LOGOUT_SUCCESS, s.auth_state, AUTH_UNAUTH);

    printf("\n");
}

/*
 * Scenario 2: Access Before Login
 *   GET /status while UNAUTH → DENIED
 *   Demonstrates: EverParse enforces auth requirement
 */
static void scenario_2(void)
{
    Session s;
    session_init(&s);
    RequestResult r;

    printf("=== Scenario 2: Access Before Login ===\n");

    /* Step 1: GET /status while unauthenticated */
    r = process_simple_request(&s, PATH_STATUS, METHOD_GET);
    check_step("GET /status while UNAUTH",
               r, RESULT_DENIED, s.auth_state, AUTH_UNAUTH);

    printf("\n");
}

/*
 * Scenario 3: Bad Credentials (Two-Layer Defense)
 *   Login with wrong password → EverParse ACCEPTS (format ok)
 *   but app REJECTS (wrong password). State stays UNAUTH.
 *   Then GET /status → DENIED (state never advanced).
 */
static void scenario_3(void)
{
    Session s;
    session_init(&s);
    RequestResult r;

    printf("=== Scenario 3: Bad Credentials (Two-Layer Defense) ===\n");

    /* Step 1: POST /login with wrong password */
    r = process_login_request(&s, "admin", 5, "wrongpassword", 13);
    check_step("POST /login with wrong password (EverParse accepts, app rejects)",
               r, RESULT_LOGIN_FAILED, s.auth_state, AUTH_UNAUTH);

    /* Step 2: GET /status (still unauthenticated — state never changed) */
    r = process_simple_request(&s, PATH_STATUS, METHOD_GET);
    check_step("GET /status still UNAUTH (state never advanced)",
               r, RESULT_DENIED, s.auth_state, AUTH_UNAUTH);

    printf("\n");
}

/*
 * Scenario 4: Logout Revokes Access
 *   Login → access → logout → access denied
 *   Demonstrates: state regression (AUTH → UNAUTH) works
 */
static void scenario_4(void)
{
    Session s;
    session_init(&s);
    RequestResult r;

    printf("=== Scenario 4: Logout Revokes Access ===\n");

    /* Step 1: POST /login with valid credentials */
    r = process_login_request(&s, "admin", 5, "secret123", 9);
    check_step("POST /login with valid creds",
               r, RESULT_LOGIN_SUCCESS, s.auth_state, AUTH_OK);

    /* Step 2: GET /status (authenticated) */
    r = process_simple_request(&s, PATH_STATUS, METHOD_GET);
    check_step("GET /status (authenticated)",
               r, RESULT_STATUS_OK, s.auth_state, AUTH_OK);

    /* Step 3: POST /logout */
    r = process_simple_request(&s, PATH_LOGOUT, METHOD_POST);
    check_step("POST /logout",
               r, RESULT_LOGOUT_SUCCESS, s.auth_state, AUTH_UNAUTH);

    /* Step 4: GET /status (now unauthenticated again) */
    r = process_simple_request(&s, PATH_STATUS, METHOD_GET);
    check_step("GET /status after logout (DENIED)",
               r, RESULT_DENIED, s.auth_state, AUTH_UNAUTH);

    printf("\n");
}

int main(void)
{
    printf("Mealy Machine Authentication Demo\n");
    printf("EverParse-verified state-dependent access control\n");
    printf("================================================\n\n");

    scenario_1();
    scenario_2();
    scenario_3();
    scenario_4();

    printf("================================================\n");
    printf("Results: %d/%d tests passed\n", total_passed, total_tests);

    if (total_passed == total_tests) {
        printf("\nAll scenarios passed. Verified Mealy machine confirmed:\n");
        printf("  - State transitions work (UNAUTH -> AUTH -> UNAUTH)\n");
        printf("  - EverParse enforces auth requirements (deny-by-default)\n");
        printf("  - Two-layer defense: format validation + credential check\n");
        printf("  - Logout revokes access (state regression)\n");
    }

    return (total_passed == total_tests) ? 0 : 1;
}
