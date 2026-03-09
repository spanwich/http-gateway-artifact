/*
 * RBAC Policy System — Application Logic Header
 *
 * Glue code between test harness and EverParse validators.
 * Maintains session state and active policy, dispatches to
 * the correct verified validator based on request type.
 */

#ifndef RBAC_APP_H
#define RBAC_APP_H

#include <stdint.h>

/* Role levels (must match RbacPolicy.3d) */
#define ROLE_NONE     0
#define ROLE_OPERATOR 1
#define ROLE_ADMIN    2

/* HTTP methods (must match RbacPolicy.3d) */
#define METHOD_GET    1
#define METHOD_POST   2
#define METHOD_PUT    3

/* Path hashes (must match RbacPolicy.3d) */
#define PATH_LOGIN    0x11111111u
#define PATH_LOGOUT   0x22222222u
#define PATH_STATUS   0x33333333u
#define PATH_POLICY   0x44444444u
#define DEAD_HASH     0xDEADDEADu

/* Limits (must match RbacPolicy.3d) */
#define MAX_RATE      50
#define MAX_RULES     8

/* Request processing results */
typedef enum {
    RESULT_DENIED,
    RESULT_LOGIN_SUCCESS,
    RESULT_LOGIN_FAILED,
    RESULT_LOGOUT_SUCCESS,
    RESULT_STATUS_OK,
    RESULT_POLICY_READ_OK,
    RESULT_POLICY_UPDATED,
    RESULT_POLICY_REJECTED,
} RequestResult;

/* A single policy rule */
typedef struct {
    uint32_t path_hash;
    uint8_t  method;
    uint8_t  min_role;
} PolicyRule;

/* Active policy */
typedef struct {
    uint8_t    num_rules;
    PolicyRule rules[MAX_RULES];
} Policy;

/* Session state */
typedef struct {
    uint8_t auth_state;   /* ROLE_NONE, ROLE_OPERATOR, or ROLE_ADMIN */
    uint8_t rate_count;
} Session;

/* Credential entry */
typedef struct {
    const char *username;
    const char *password;
    uint8_t     role;
} Credential;

/* Initialize session to default state */
void session_init(Session *s);

/* Reset session (for testing multiple scenarios) */
void session_reset(Session *s);

/* Initialize policy with default rules */
void policy_init_default(Policy *p);

/*
 * Process a request through the verified dispatch pipeline.
 *
 * Dispatch logic:
 *   POST /login  -> LoginValidator  -> credential check -> set role
 *   PUT  /policy -> PolicyBlobValidator -> format check -> update policy
 *   everything else -> AccessRequest validator -> policy enforcement
 *
 * body/body_len used for login credentials or policy blob.
 * For login: body = [username_len][username][password_len][password]
 * For policy update: body = [num_rules][rule_0:6]...[rule_7:6]
 */
RequestResult process_request(Session *s, Policy *p,
                              uint32_t path_hash, uint8_t method,
                              const uint8_t *body, uint32_t body_len);

/* Get human-readable result name */
const char *result_name(RequestResult r);

/* Get human-readable role name */
const char *role_name(uint8_t role);

#endif /* RBAC_APP_H */
