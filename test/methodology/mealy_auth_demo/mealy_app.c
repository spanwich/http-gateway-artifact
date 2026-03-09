/*
 * Mealy Machine Authentication Demo — Application Logic Implementation
 *
 * Three layers:
 *   1. This glue code: maintains state, constructs buffers, dispatches
 *   2. EverParse validators: verified accept/reject (F*-checked)
 *   3. App logic: credential comparison, state transitions
 */

#include "mealy_app.h"
#include "generated/MealyAuthWrapper.h"
#include <string.h>
#include <stdio.h>

/*
 * Buffer layout constants (must match MealyAuth.3d struct layout).
 *
 * Common header:
 *   [0]     auth_state   (UINT8)
 *   [1]     rate_count   (UINT8)
 *   [2..5]  path_hash    (UINT32 LE)
 *   [6]     method       (UINT8)
 *   [7]     _check       (UINT8, value irrelevant — constraint uses other fields)
 *
 * Login body (after header):
 *   [8]           username_len  (UINT8)
 *   [9..8+N]      username      (N bytes)
 *   [9+N]         password_len  (UINT8)
 *   [10+N..9+N+M] password      (M bytes)
 */
#define HEADER_SIZE 8   /* auth_state + rate_count + path_hash + method + _check */

/* Required by EverParse generated wrapper */
void MealyAuthEverParseError(
    const char *struct_name,
    const char *field_name,
    const char *reason)
{
    (void)struct_name; (void)field_name; (void)reason;
}

/* Write common header into buffer. Returns header size. */
static uint32_t write_header(uint8_t *buf, const Session *s,
                              uint32_t path_hash, uint8_t method)
{
    buf[0] = s->auth_state;
    buf[1] = s->rate_count;
    /* path_hash: little-endian UINT32 */
    buf[2] = (path_hash >>  0) & 0xFF;
    buf[3] = (path_hash >>  8) & 0xFF;
    buf[4] = (path_hash >> 16) & 0xFF;
    buf[5] = (path_hash >> 24) & 0xFF;
    buf[6] = method;
    buf[7] = 0x00; /* _check byte — value irrelevant, constraint reads other fields */
    return HEADER_SIZE;
}

void session_init(Session *s)
{
    s->auth_state = AUTH_UNAUTH;
    s->rate_count = 0;
    strncpy(s->valid_username, "admin", sizeof(s->valid_username) - 1);
    s->valid_username[sizeof(s->valid_username) - 1] = '\0';
    strncpy(s->valid_password, "secret123", sizeof(s->valid_password) - 1);
    s->valid_password[sizeof(s->valid_password) - 1] = '\0';
}

void session_reset(Session *s)
{
    session_init(s);
}

RequestResult process_simple_request(Session *s, uint32_t path_hash, uint8_t method)
{
    uint8_t buf[HEADER_SIZE];
    write_header(buf, s, path_hash, method);

    BOOLEAN accepted;
    if (path_hash == PATH_LOGOUT) {
        accepted = MealyAuthCheckLogoutRequest(buf, HEADER_SIZE);
    } else if (path_hash == PATH_STATUS) {
        accepted = MealyAuthCheckStatusRequest(buf, HEADER_SIZE);
    } else {
        /* Unknown request type — no validator exists → denied */
        s->rate_count++;
        return RESULT_DENIED;
    }

    s->rate_count++;

    if (!accepted) {
        return RESULT_DENIED;
    }

    /* EverParse accepted — execute application logic */
    if (path_hash == PATH_LOGOUT) {
        s->auth_state = AUTH_UNAUTH;
        return RESULT_LOGOUT_SUCCESS;
    } else { /* PATH_STATUS */
        return RESULT_STATUS_OK;
    }
}

RequestResult process_login_request(Session *s,
                                    const char *username, uint8_t username_len,
                                    const char *password, uint8_t password_len)
{
    /*
     * Buffer: header + username_len(1) + username(N) + password_len(1) + password(M)
     * Max: 8 + 1 + 32 + 1 + 64 = 106 bytes
     */
    uint8_t buf[HEADER_SIZE + 1 + 32 + 1 + 64];
    uint32_t pos = write_header(buf, s, PATH_LOGIN, METHOD_POST);

    /* Append credential fields */
    buf[pos++] = username_len;
    memcpy(buf + pos, username, username_len);
    pos += username_len;

    buf[pos++] = password_len;
    memcpy(buf + pos, password, password_len);
    pos += password_len;

    /* Layer 1: EverParse structural validation (verified) */
    BOOLEAN accepted = MealyAuthCheckLoginRequest(buf, pos);

    s->rate_count++;

    if (!accepted) {
        return RESULT_DENIED;
    }

    /*
     * Layer 2: App-level credential check (unverified but simple).
     *
     * EverParse already validated:
     *   - path_hash == PATH_LOGIN
     *   - method == METHOD_POST
     *   - rate_count < MAX_RATE
     *   - 1 <= username_len <= 32
     *   - 1 <= password_len <= 64
     *
     * Now we check if the credentials are actually correct.
     * State only advances on correct credentials.
     */
    if (username_len == (uint8_t)strlen(s->valid_username) &&
        password_len == (uint8_t)strlen(s->valid_password) &&
        memcmp(username, s->valid_username, username_len) == 0 &&
        memcmp(password, s->valid_password, password_len) == 0)
    {
        s->auth_state = AUTH_OK;
        return RESULT_LOGIN_SUCCESS;
    }

    /* Credentials wrong — EverParse accepted (format ok) but app rejected */
    return RESULT_LOGIN_FAILED;
}

const char *result_name(RequestResult r)
{
    switch (r) {
    case RESULT_DENIED:         return "DENIED";
    case RESULT_LOGIN_SUCCESS:  return "LOGIN_SUCCESS";
    case RESULT_LOGIN_FAILED:   return "LOGIN_FAILED";
    case RESULT_LOGOUT_SUCCESS: return "LOGOUT_SUCCESS";
    case RESULT_STATUS_OK:      return "STATUS_OK";
    default:                    return "UNKNOWN";
    }
}

const char *auth_state_name(uint8_t state)
{
    switch (state) {
    case AUTH_UNAUTH: return "UNAUTH";
    case AUTH_OK:     return "AUTH";
    default:          return "UNKNOWN";
    }
}
