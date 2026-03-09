/*
 * Batch C: Multi-Session E2E Pipeline — Central Header
 *
 * Defines domain constants, types, and pipeline entry point.
 * Includes session.h and mock_extractor.h.
 */

#ifndef PIPELINE_H
#define PIPELINE_H

#include <stdint.h>
#include "session.h"
#include "mock_extractor.h"

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
    RESULT_EXTRACTION_FAILED,
    RESULT_NO_SESSION
} RequestResult;

/* A single policy rule */
typedef struct {
    uint32_t path_hash;
    uint8_t  method;
    uint8_t  min_role;
    uint16_t req_scope;
} PolicyRule;

/* Active policy */
typedef struct {
    uint8_t    num_rules;
    PolicyRule rules[MAX_RULES];
} Policy;

/* Credential entry */
typedef struct {
    const char *username;
    const char *password;
    uint8_t     role;
} Credential;

/* Pipeline entry point */
RequestResult pipeline_process(SessionTable *sessions, Policy *policy,
                               uint32_t client_id, const MockHTTPRequest *req);

void policy_init_default(Policy *p);
const char *result_name(RequestResult r);
const char *role_name(uint8_t role);

#endif /* PIPELINE_H */
