/*
 * Authenticator.c -- CAmkES component: IdP + PIP (passive, RPC-driven)
 *
 * Provides login (credential verification + token generation) and
 * validate (token verification + claims extraction) via seL4RPCCall.
 *
 * Request/response data goes through shared auth_dp dataport.
 * RPC carries lengths and returns response length.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <camkes.h>
#include <stdio.h>
#include <string.h>

#include "auth_wire.h"
#include "credential_store.h"
#include "token_generate.h"
#include "token_validate.h"

/*
 * login(cred_len) -- authenticate credentials from auth_dp
 *
 * Input (auth_dp):  [ulen:1][username:N][plen:1][password:M]
 * Output (auth_dp): [valid:1][role:1][scope:2(LE)][sub_len:1][sub:N][tok_len:1][tok:M]
 * Returns: response length in auth_dp
 */
int auth_login(int cred_len)
{
    volatile uint8_t *dp = (volatile uint8_t *)auth_dp;

    if (cred_len < 4 || cred_len > 256) {
        dp[0] = 0; /* invalid */
        printf("[Authenticator] login: bad cred_len=%d\n", cred_len);
        return 1;
    }

    /* Copy from volatile dataport to local buffer */
    uint8_t buf[256];
    for (int i = 0; i < cred_len; i++) buf[i] = dp[i];

    /* Parse: [ulen:1][username:N][plen:1][password:M] */
    uint8_t ulen = buf[0];
    if (1 + ulen + 1 > (uint32_t)cred_len) {
        dp[0] = 0;
        printf("[Authenticator] login: bad ulen=%u\n", ulen);
        return 1;
    }
    const char *username = (const char *)&buf[1];
    uint8_t plen = buf[1 + ulen];
    if (1 + ulen + 1 + plen > (uint32_t)cred_len) {
        dp[0] = 0;
        printf("[Authenticator] login: bad plen=%u\n", plen);
        return 1;
    }
    const char *password = (const char *)&buf[1 + ulen + 1];

    /* Verify credentials */
    uint8_t role = 0;
    uint16_t scope = 0;
    uint8_t subject_id[SUBJECT_ID_MAX];
    uint8_t subject_id_len = 0;

    int ok = verify_credentials(username, ulen, password, plen,
                                &role, &scope, subject_id, &subject_id_len);
    if (!ok) {
        dp[0] = 0;
        printf("[Authenticator] login: invalid credentials\n");
        return 1;
    }

    /* Generate token */
    char token[128];
    uint8_t token_len = 0;
    ok = generate_token((const char *)subject_id, subject_id_len,
                        role, scope, token, &token_len);
    if (!ok) {
        dp[0] = 0;
        printf("[Authenticator] login: token generation failed\n");
        return 1;
    }

    /* Build response in local buffer, then write to dataport */
    uint8_t resp[256];
    int pos = 0;
    resp[pos++] = 1; /* valid */
    resp[pos++] = role;
    resp[pos++] = (uint8_t)(scope & 0xFF);
    resp[pos++] = (uint8_t)((scope >> 8) & 0xFF);
    resp[pos++] = subject_id_len;
    memcpy(resp + pos, subject_id, subject_id_len);
    pos += subject_id_len;
    resp[pos++] = token_len;
    memcpy(resp + pos, token, token_len);
    pos += token_len;

    /* Write response to dataport */
    for (int i = 0; i < pos; i++) dp[i] = resp[i];

    printf("[Authenticator] login: OK role=%u scope=0x%04x tok_len=%u\n",
           role, scope, token_len);
    return pos;
}

/*
 * validate(token_len) -- validate token from auth_dp
 *
 * Input (auth_dp):  [token:N]  (raw token string)
 * Output (auth_dp): [valid:1][role:1][scope:2(LE)][sub_len:1][sub:N]
 * Returns: response length in auth_dp
 */
int auth_validate(int token_len)
{
    volatile uint8_t *dp = (volatile uint8_t *)auth_dp;

    if (token_len <= 0 || token_len > 127) {
        dp[0] = 0;
        return 1;
    }

    /* Copy token from volatile dataport */
    char token[128];
    for (int i = 0; i < token_len; i++) token[i] = (char)dp[i];

    uint8_t role = 0;
    uint16_t scope = 0;
    char subject[SUBJECT_ID_MAX];
    uint8_t subject_len = 0;

    int ok = validate_token(token, (uint8_t)token_len,
                            &role, &scope, subject, &subject_len);
    if (!ok) {
        dp[0] = 0;
        printf("[Authenticator] validate: invalid token\n");
        return 1;
    }

    /* Build response */
    uint8_t resp[64];
    int pos = 0;
    resp[pos++] = 1; /* valid */
    resp[pos++] = role;
    resp[pos++] = (uint8_t)(scope & 0xFF);
    resp[pos++] = (uint8_t)((scope >> 8) & 0xFF);
    resp[pos++] = subject_len;
    memcpy(resp + pos, subject, subject_len);
    pos += subject_len;

    /* Write response to dataport */
    for (int i = 0; i < pos; i++) dp[i] = resp[i];

    printf("[Authenticator] validate: OK role=%u scope=0x%04x\n", role, scope);
    return pos;
}
