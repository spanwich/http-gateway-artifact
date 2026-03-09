/*
 * Mealy Machine Authentication Demo — Application Logic
 *
 * Glue code between the test harness and EverParse validators.
 * Maintains session state and dispatches to the appropriate
 * verified validator based on request type.
 */

#ifndef MEALY_APP_H
#define MEALY_APP_H

#include <stdint.h>

/* Auth states */
#define AUTH_UNAUTH 0
#define AUTH_OK     1

/* HTTP methods */
#define METHOD_GET  1
#define METHOD_POST 2

/* Path hashes (must match MealyAuth.3d) */
#define PATH_LOGIN  0x11111111u
#define PATH_LOGOUT 0x22222222u
#define PATH_STATUS 0x33333333u

/* Rate limit (must match MealyAuth.3d) */
#define MAX_RATE 50

/* Request processing results */
typedef enum {
    RESULT_DENIED,          /* EverParse rejected the request */
    RESULT_LOGIN_SUCCESS,   /* Credentials correct, now AUTH_OK */
    RESULT_LOGIN_FAILED,    /* Credentials wrong, still UNAUTH */
    RESULT_LOGOUT_SUCCESS,  /* Now UNAUTH */
    RESULT_STATUS_OK,       /* Authorized status query */
} RequestResult;

/* Session state */
typedef struct {
    uint8_t auth_state;       /* AUTH_UNAUTH or AUTH_OK */
    uint8_t rate_count;       /* Requests this window */
    char valid_username[33];  /* Expected username (null-terminated) */
    char valid_password[65];  /* Expected password (null-terminated) */
} Session;

/* Initialize session to default state */
void session_init(Session *s);

/* Reset session (for testing multiple scenarios) */
void session_reset(Session *s);

/*
 * Process a simple request (no body): logout or status.
 *
 * Constructs [auth_state, rate_count, path_hash, method, _check]
 * buffer and calls the appropriate EverParse validator.
 */
RequestResult process_simple_request(Session *s, uint32_t path_hash, uint8_t method);

/*
 * Process a login request with credentials.
 *
 * Constructs [auth_state, rate_count, path_hash, method, _check,
 *             username_len, username, password_len, password]
 * buffer and calls EverParse LoginRequest validator.
 *
 * Two-layer defense:
 *   1. EverParse validates structure (format ok, login attempt permitted)
 *   2. App logic validates credentials (correct password)
 *   State only advances if BOTH layers pass.
 */
RequestResult process_login_request(Session *s,
                                    const char *username, uint8_t username_len,
                                    const char *password, uint8_t password_len);

/* Get human-readable result name */
const char *result_name(RequestResult r);

/* Get human-readable auth state name */
const char *auth_state_name(uint8_t state);

#endif /* MEALY_APP_H */
