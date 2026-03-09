/*
 * RBAC Policy System — Application Logic Implementation
 *
 * Three layers:
 *   1. This glue code: maintains state, constructs buffers, dispatches
 *   2. EverParse validators: verified accept/reject (F*-checked)
 *   3. App logic: credential comparison, state transitions, policy updates
 */

#include "rbac_app.h"
#include "generated/RbacPolicyWrapper.h"
#include <string.h>
#include <stdio.h>

/* Credential table */
static const Credential credentials[] = {
    { "operator", "oper123",  ROLE_OPERATOR },
    { "admin",    "admin456", ROLE_ADMIN    },
};
#define NUM_CREDENTIALS (sizeof(credentials) / sizeof(credentials[0]))

/*
 * Buffer layout constants (must match RbacPolicy.3d struct layouts):
 *
 * LoginRequest:
 *   [0]     auth_state  (UINT8)
 *   [1]     rate_count  (UINT8)
 *   [2..5]  path_hash   (UINT32 LE)
 *   [6]     method      (UINT8)
 *   [7]     _check      (UINT8)
 *   [8]     username_len (UINT8)
 *   [9..8+N] username
 *   [9+N]   password_len (UINT8)
 *   [10+N..] password
 *
 * PolicyBlob:
 *   [0]     auth_state  (UINT8)
 *   [1]     rate_count  (UINT8)
 *   [2]     num_rules   (UINT8)
 *   [3..50] 8 rules * 6 bytes = 48 bytes
 *   [51]    _auth_ok    (UINT8)
 *   [52]    _rate_ok    (UINT8)
 *   [53]    _rules_ok   (UINT8)
 *   Total: 54 bytes
 *
 * AccessRequest:
 *   [0]     auth_state  (UINT8)
 *   [1]     rate_count  (UINT8)
 *   [2..49] 8 rules * 6 bytes = 48 bytes
 *   [50..53] req_path_hash (UINT32 LE)
 *   [54]    req_method  (UINT8)
 *   [55]    _rate_ok    (UINT8)
 *   [56]    _access_ok  (UINT8)
 *   Total: 57 bytes
 */

#define LOGIN_HEADER_SIZE 8   /* auth_state + rate_count + path_hash + method + _check */
#define POLICY_BLOB_SIZE  54  /* 3 + 48 + 3 */
#define ACCESS_REQ_SIZE   57  /* 2 + 48 + 5 + 2 */

/* Required by EverParse generated wrapper */
void RbacPolicyEverParseError(
    const char *struct_name,
    const char *field_name,
    const char *reason)
{
    (void)struct_name; (void)field_name; (void)reason;
}

/* Write a UINT32 in little-endian */
static void write_u32(uint8_t *buf, int offset, uint32_t val)
{
    buf[offset + 0] = (val >>  0) & 0xFF;
    buf[offset + 1] = (val >>  8) & 0xFF;
    buf[offset + 2] = (val >> 16) & 0xFF;
    buf[offset + 3] = (val >> 24) & 0xFF;
}

/* Write a policy rule (6 bytes) at offset */
static void write_rule(uint8_t *buf, int offset, const PolicyRule *r)
{
    write_u32(buf, offset, r->path_hash);
    buf[offset + 4] = r->method;
    buf[offset + 5] = r->min_role;
}

/* Write all 8 rules starting at offset */
static void write_rules(uint8_t *buf, int offset, const Policy *p)
{
    for (int i = 0; i < MAX_RULES; i++) {
        write_rule(buf, offset + i * 6, &p->rules[i]);
    }
}

void session_init(Session *s)
{
    s->auth_state = ROLE_NONE;
    s->rate_count = 0;
}

void session_reset(Session *s)
{
    session_init(s);
}

void policy_init_default(Policy *p)
{
    p->num_rules = 3;

    /* Rule 0: GET /status requires OPERATOR */
    p->rules[0] = (PolicyRule){ PATH_STATUS, METHOD_GET, ROLE_OPERATOR };

    /* Rule 1: POST /logout requires OPERATOR */
    p->rules[1] = (PolicyRule){ PATH_LOGOUT, METHOD_POST, ROLE_OPERATOR };

    /* Rule 2: GET /policy requires ADMIN */
    p->rules[2] = (PolicyRule){ PATH_POLICY, METHOD_GET, ROLE_ADMIN };

    /* Rules 3-7: unused (DEAD_HASH) */
    for (int i = 3; i < MAX_RULES; i++) {
        p->rules[i] = (PolicyRule){ DEAD_HASH, 0, 0 };
    }
}

/*
 * Process POST /login
 *
 * body format: [username_len:1][username:N][password_len:1][password:M]
 */
static RequestResult handle_login(Session *s, const uint8_t *body, uint32_t body_len)
{
    if (body == NULL || body_len < 2) {
        return RESULT_DENIED;
    }

    uint8_t username_len = body[0];
    if ((uint32_t)(1 + username_len + 1) > body_len) {
        return RESULT_DENIED;
    }
    const uint8_t *username = body + 1;

    uint8_t password_len = body[1 + username_len];
    if ((uint32_t)(1 + username_len + 1 + password_len) > body_len) {
        return RESULT_DENIED;
    }
    const uint8_t *password = body + 1 + username_len + 1;

    /* Build login buffer:
     * [auth_state][rate_count][path_hash LE][method][_check]
     * [username_len][username...][password_len][password...]
     */
    uint8_t buf[LOGIN_HEADER_SIZE + 1 + 32 + 1 + 64];
    buf[0] = s->auth_state;
    buf[1] = s->rate_count;
    write_u32(buf, 2, PATH_LOGIN);
    buf[6] = METHOD_POST;
    buf[7] = 0x00; /* _check byte */

    uint32_t pos = LOGIN_HEADER_SIZE;
    buf[pos++] = username_len;
    memcpy(buf + pos, username, username_len);
    pos += username_len;
    buf[pos++] = password_len;
    memcpy(buf + pos, password, password_len);
    pos += password_len;

    /* Layer 1: EverParse structural validation */
    BOOLEAN accepted = RbacPolicyCheckLoginRequest(buf, pos);

    s->rate_count++;

    if (!accepted) {
        return RESULT_DENIED;
    }

    /* Layer 2: credential check */
    for (unsigned i = 0; i < NUM_CREDENTIALS; i++) {
        const Credential *c = &credentials[i];
        uint8_t ulen = (uint8_t)strlen(c->username);
        uint8_t plen = (uint8_t)strlen(c->password);
        if (username_len == ulen && password_len == plen &&
            memcmp(username, c->username, ulen) == 0 &&
            memcmp(password, c->password, plen) == 0)
        {
            s->auth_state = c->role;
            return RESULT_LOGIN_SUCCESS;
        }
    }

    return RESULT_LOGIN_FAILED;
}

/*
 * Process PUT /policy
 *
 * body format: [num_rules:1][rule_0:6][rule_1:6]...[rule_7:6]
 * Total body: 1 + 48 = 49 bytes
 */
static RequestResult handle_policy_update(Session *s, Policy *p,
                                          const uint8_t *body, uint32_t body_len)
{
    if (body == NULL || body_len < 49) {
        return RESULT_DENIED;
    }

    uint8_t num_rules = body[0];

    /* Build PolicyBlob buffer:
     * [auth_state][rate_count][num_rules]
     * [rule_0:6]...[rule_7:6]
     * [_auth_ok][_rate_ok][_rules_ok]
     */
    uint8_t buf[POLICY_BLOB_SIZE];
    memset(buf, 0, POLICY_BLOB_SIZE);
    buf[0] = s->auth_state;
    buf[1] = s->rate_count;
    buf[2] = num_rules;
    memcpy(buf + 3, body + 1, 48); /* Copy 8 rules */
    /* Check bytes at 51, 52, 53 already zeroed by memset */

    BOOLEAN accepted = RbacPolicyCheckPolicyBlob(buf, POLICY_BLOB_SIZE);

    s->rate_count++;

    if (!accepted) {
        return RESULT_DENIED;
    }

    /* Policy format valid and uploader is ADMIN — update active policy */
    p->num_rules = num_rules;
    for (int i = 0; i < MAX_RULES; i++) {
        int off = 1 + i * 6; /* offset in body */
        p->rules[i].path_hash =
            (uint32_t)body[off + 0] |
            ((uint32_t)body[off + 1] << 8) |
            ((uint32_t)body[off + 2] << 16) |
            ((uint32_t)body[off + 3] << 24);
        p->rules[i].method = body[off + 4];
        p->rules[i].min_role = body[off + 5];
    }

    return RESULT_POLICY_UPDATED;
}

/*
 * Process general access request (not login, not policy PUT)
 */
static RequestResult handle_access_request(Session *s, const Policy *p,
                                           uint32_t path_hash, uint8_t method)
{
    /* Build AccessRequest buffer:
     * [auth_state][rate_count]
     * [rule_0:6]...[rule_7:6]   (48 bytes)
     * [req_path_hash:4][req_method:1]
     * [_rate_ok:1][_access_ok:1]
     */
    uint8_t buf[ACCESS_REQ_SIZE];
    memset(buf, 0, ACCESS_REQ_SIZE);

    buf[0] = s->auth_state;
    buf[1] = s->rate_count;
    write_rules(buf, 2, p);
    write_u32(buf, 50, path_hash);
    buf[54] = method;
    /* _rate_ok at 55, _access_ok at 56 — already zeroed */

    BOOLEAN accepted = RbacPolicyCheckAccessRequest(buf, ACCESS_REQ_SIZE);

    s->rate_count++;

    if (!accepted) {
        return RESULT_DENIED;
    }

    /* Dispatch to endpoint */
    if (path_hash == PATH_LOGOUT && method == METHOD_POST) {
        s->auth_state = ROLE_NONE;
        return RESULT_LOGOUT_SUCCESS;
    } else if (path_hash == PATH_STATUS && method == METHOD_GET) {
        return RESULT_STATUS_OK;
    } else if (path_hash == PATH_POLICY && method == METHOD_GET) {
        return RESULT_POLICY_READ_OK;
    }

    /* Valid per policy but unknown endpoint — still return OK */
    return RESULT_STATUS_OK;
}

RequestResult process_request(Session *s, Policy *p,
                              uint32_t path_hash, uint8_t method,
                              const uint8_t *body, uint32_t body_len)
{
    /* Dispatch: login and policy upload have their own validators */
    if (path_hash == PATH_LOGIN && method == METHOD_POST) {
        return handle_login(s, body, body_len);
    }

    if (path_hash == PATH_POLICY && method == METHOD_PUT) {
        return handle_policy_update(s, p, body, body_len);
    }

    /* Everything else goes through AccessRequest validator */
    return handle_access_request(s, p, path_hash, method);
}

const char *result_name(RequestResult r)
{
    switch (r) {
    case RESULT_DENIED:          return "DENIED";
    case RESULT_LOGIN_SUCCESS:   return "LOGIN_SUCCESS";
    case RESULT_LOGIN_FAILED:    return "LOGIN_FAILED";
    case RESULT_LOGOUT_SUCCESS:  return "LOGOUT_SUCCESS";
    case RESULT_STATUS_OK:       return "STATUS_OK";
    case RESULT_POLICY_READ_OK:  return "POLICY_READ_OK";
    case RESULT_POLICY_UPDATED:  return "POLICY_UPDATED";
    case RESULT_POLICY_REJECTED: return "POLICY_REJECTED";
    default:                     return "UNKNOWN";
    }
}

const char *role_name(uint8_t role)
{
    switch (role) {
    case ROLE_NONE:     return "NONE";
    case ROLE_OPERATOR: return "OPERATOR";
    case ROLE_ADMIN:    return "ADMIN";
    default:            return "UNKNOWN";
    }
}
