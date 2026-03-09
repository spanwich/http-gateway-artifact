/*
 * auth_wire.h -- Shared dataport protocol for FStarExtractor <-> Authenticator
 *
 * The auth_dp dataport (4096 bytes) carries request and response data.
 * RPC login(cred_len)/validate(token_len) triggers the operation.
 * After RPC returns, response data is in the same dataport.
 *
 * Login request (FStarExtractor writes):
 *   [ulen:1][username:N][plen:1][password:M]
 *
 * Login response (Authenticator writes, RPC returns resp_len):
 *   [valid:1][role:1][scope:2(LE)][sub_len:1][sub:N][tok_len:1][tok:M]
 *
 * Validate request (FStarExtractor writes):
 *   [token:N]  (raw token string, length passed via RPC)
 *
 * Validate response (Authenticator writes, RPC returns resp_len):
 *   [valid:1][role:1][scope:2(LE)][sub_len:1][sub:N]
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef AUTH_WIRE_H
#define AUTH_WIRE_H

#include <stdint.h>

#define AUTH_DP_SIZE  4096

/* Login response offsets */
#define AUTH_RESP_VALID     0
#define AUTH_RESP_ROLE      1
#define AUTH_RESP_SCOPE_LO  2
#define AUTH_RESP_SCOPE_HI  3
#define AUTH_RESP_SUB_LEN   4
#define AUTH_RESP_SUB_START 5
/* tok_len at AUTH_RESP_SUB_START + sub_len */
/* tok at AUTH_RESP_SUB_START + sub_len + 1 */

#endif /* AUTH_WIRE_H */
