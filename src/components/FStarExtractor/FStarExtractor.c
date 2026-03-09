/*
 * FStarExtractor.c -- CAmkES component: PEP + PIP relay (Phase 4)
 *
 * Receives raw HTTP bytes from LwipProxy (Link 3 forward ring).
 * Runs extract_security_params() to produce SecurityParamsWire.
 *
 * Auth routing (Phase 4):
 *   - POST /api/login -> Authenticator IPC (login) -> HTTP response directly
 *   - POST /api/logout -> HTTP 200 directly (stateless, client-side)
 *   - Protected endpoints without token -> HTTP 401
 *   - Protected endpoints with token -> Authenticator IPC (validate)
 *       -> If invalid: HTTP 403
 *       -> If valid: fill role/scope/subject into SecurityParamsWire
 *          -> Forward to PolicyGate via Link 4
 *   - Dashboard (GET /) -> served directly before extraction
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <camkes.h>
#include <sel4/sel4.h>

#include "web_common.h"
#include "extract.h"
#include "HTTP_Extract_Complete.h"
#include "IPC_Extract.h"
#include "security_params_wire.h"
#include "gate_response_wire.h"
#include "path_hashes.h"
#include "auth_wire.h"
#include "http_response.h"
#include "dashboard_html.h"

/* HTTP response template for dashboard */
static const char RESP_200_HTML[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_404_BODY[] =
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{\"error\":\"unknown endpoint\"}";

/* Write a complete frame to a ring buffer */
static void write_to_ring(volatile struct ring_dataport *ring,
                           const uint8_t *data, uint32_t len)
{
    if (len > WEB_FRAME_MTU) len = WEB_FRAME_MTU;

    struct frame_entry *slot = ring_produce(ring);
    if (!slot) {
        printf("[FStarExtractor] WARN: ring full, dropping %u bytes\n",
               (unsigned)len);
        return;
    }

    slot->len = (uint16_t)len;
    memcpy(slot->data, data, len);
    ring_commit(ring);
}

static int is_dashboard_request(const uint8_t *buf, uint16_t len)
{
    if (len >= 6 && memcmp(buf, "GET / ", 6) == 0) return 1;
    if (len >= 6 && memcmp(buf, "GET /?", 6) == 0) return 1;
    return 0;
}

static void write_dashboard_response(volatile struct ring_dataport *ring)
{
    uint8_t resp_buf[WEB_FRAME_MTU];
    uint32_t hdr_len = (uint32_t)(sizeof(RESP_200_HTML) - 1);
    uint32_t total = hdr_len + dashboard_html_len;
    if (total > WEB_FRAME_MTU) total = WEB_FRAME_MTU;
    memcpy(resp_buf, RESP_200_HTML, hdr_len);
    uint32_t body_copy = total - hdr_len;
    if (body_copy > dashboard_html_len) body_copy = dashboard_html_len;
    memcpy(resp_buf + hdr_len, dashboard_html, body_copy);
    write_to_ring(ring, resp_buf, total);
}

/* ------------------------------------------------------------------ */
/* JSON login body -> binary credential conversion                     */
/* Parse {"username":"X","password":"Y"} -> [ulen:1][user:N][plen:1][pass:M] */
/* ------------------------------------------------------------------ */

static uint16_t parse_login_body(const uint8_t *body, uint32_t body_len,
                                  uint8_t *out, uint16_t out_max)
{
    const char *ukey = "\"username\":\"";
    const char *pkey = "\"password\":\"";
    const unsigned ukey_len = 12;
    const unsigned pkey_len = 12;

    const uint8_t *ustart = NULL;
    uint8_t ulen = 0;
    const uint8_t *pstart = NULL;
    uint8_t plen = 0;

    for (uint32_t i = 0; i + ukey_len < body_len; i++) {
        if (memcmp(body + i, ukey, ukey_len) == 0) {
            ustart = body + i + ukey_len;
            uint32_t j = i + ukey_len;
            while (j < body_len && body[j] != '"') j++;
            ulen = (uint8_t)(j - (i + ukey_len));
            break;
        }
    }

    for (uint32_t i = 0; i + pkey_len < body_len; i++) {
        if (memcmp(body + i, pkey, pkey_len) == 0) {
            pstart = body + i + pkey_len;
            uint32_t j = i + pkey_len;
            while (j < body_len && body[j] != '"') j++;
            plen = (uint8_t)(j - (i + pkey_len));
            break;
        }
    }

    if (!ustart || !pstart || ulen == 0 || plen == 0) return 0;
    if ((uint16_t)(1 + ulen + 1 + plen) > out_max) return 0;

    out[0] = ulen;
    memcpy(out + 1, ustart, ulen);
    out[1 + ulen] = plen;
    memcpy(out + 1 + ulen + 1, pstart, plen);

    return 1 + ulen + 1 + plen;
}

/* ------------------------------------------------------------------ */
/* Auth routing helpers                                                */
/* ------------------------------------------------------------------ */

/*
 * Handle POST /api/login: parse JSON body, call Authenticator login IPC,
 * return HTTP response with token (or 401).
 */
static void handle_login(volatile struct ring_dataport *http_tx,
                         const SecurityParamsWire *params)
{
    volatile uint8_t *adp = (volatile uint8_t *)auth_dp;
    uint8_t resp_buf[WEB_FRAME_MTU];
    uint32_t resp_len = 0;

    /* Convert JSON body to binary credential format */
    uint8_t cred_bin[256];
    uint16_t cred_len = 0;

    if (params->body_len > 0) {
        cred_len = parse_login_body(params->body, params->body_len,
                                     cred_bin, sizeof(cred_bin));
    }

    if (cred_len == 0) {
        format_login_response(0, NULL, 0, resp_buf, &resp_len);
        write_to_ring(http_tx, resp_buf, resp_len);
        to_proxy_ready_emit();
        return;
    }

    /* Write credentials to auth dataport */
    for (int i = 0; i < cred_len; i++) adp[i] = cred_bin[i];

    /* Call Authenticator login RPC */
    int login_resp_len = auth_login(cred_len);

    if (login_resp_len > 1 && adp[0] == 1) {
        /* Success: extract token from response */
        uint8_t sub_len = adp[AUTH_RESP_SUB_LEN];
        uint8_t tok_len = adp[AUTH_RESP_SUB_START + sub_len];
        const char *token = (const char *)&adp[AUTH_RESP_SUB_START + sub_len + 1];

        /* Copy token to local buffer (volatile -> local) */
        char token_local[128];
        for (int i = 0; i < tok_len && i < 127; i++)
            token_local[i] = token[i];

        format_login_response(1, token_local, tok_len, resp_buf, &resp_len);

        printf("[FStarExtractor] login: OK tok_len=%u\n", tok_len);
    } else {
        format_login_response(0, NULL, 0, resp_buf, &resp_len);
        printf("[FStarExtractor] login: DENIED\n");
    }

    write_to_ring(http_tx, resp_buf, resp_len);
    to_proxy_ready_emit();
}

/*
 * Validate a bearer token via Authenticator IPC.
 * On success, fills role/scope/subject via F*-verified populate_auth_fields(),
 * then queries RateLimiter for rate count via populate_rate_field().
 * Returns 1 on success, 0 on failure.
 */
static int validate_and_fill(uint8_t *wire_buf, SecurityParamsWire *params)
{
    if (params->token_len == 0) return 0;

    volatile uint8_t *adp = (volatile uint8_t *)auth_dp;

    /* Write token to auth dataport */
    for (int i = 0; i < params->token_len && i < AUTH_TOKEN_MAX; i++)
        adp[i] = params->token[i];

    /* Call Authenticator validate RPC */
    int val_resp_len = auth_validate(params->token_len);

    if (val_resp_len > 1 && adp[0] == 1) {
        /* Valid: copy auth response to local buffer (volatile -> local) */
        uint8_t auth_local[64];
        for (int i = 0; i < val_resp_len && i < 64; i++)
            auth_local[i] = adp[i];

        /* F*-verified: populate role, scope, subject_id into wire_buf */
        populate_auth_fields(wire_buf, auth_local);

        /* Update the struct view for subsequent code (e.g. logging) */
        params->role = wire_buf[6];
        params->scope = (uint16_t)wire_buf[7] | ((uint16_t)wire_buf[8] << 8);
        params->subject_id_len = wire_buf[9];

        /* Copy subject_id to rate_dp for RateLimiter lookup */
        volatile uint8_t *rdp = (volatile uint8_t *)rate_dp;
        for (int i = 0; i < params->subject_id_len; i++)
            rdp[i] = wire_buf[10 + i];

        /* Call RateLimiter RPC */
        rate_lookup_and_increment(params->subject_id_len);

        /* Read rate count from rate_dp[0] */
        uint8_t rate_count = rdp[0];

        /* F*-verified: populate rate_count at offset 0 */
        populate_rate_field(wire_buf, rate_count);

        /* Update struct view */
        params->rate_count = rate_count;

        return 1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Main loop                                                          */
/* ------------------------------------------------------------------ */

int run(void)
{
    printf("[FStarExtractor] Starting (Phase 4: XACML auth routing)\n");

    /* Phase 4 RPC smoke test: login -> validate round-trip */
    {
        volatile uint8_t *adp = (volatile uint8_t *)auth_dp;

        adp[0] = 5;
        memcpy((void *)(adp + 1), "admin", 5);
        adp[6] = 8;
        memcpy((void *)(adp + 7), "admin456", 8);

        int lr = auth_login(15);
        if (lr > 1 && adp[0] == 1) {
            uint8_t sub_len = adp[4];
            uint8_t tok_len = adp[5 + sub_len];
            printf("[FStarExtractor] RPC smoke: login PASS (tok_len=%u)\n", tok_len);

            uint8_t token_buf[128];
            for (int i = 0; i < tok_len; i++)
                token_buf[i] = adp[5 + sub_len + 1 + i];
            for (int i = 0; i < tok_len; i++)
                adp[i] = token_buf[i];

            int vr = auth_validate(tok_len);
            if (vr > 1 && adp[0] == 1)
                printf("[FStarExtractor] RPC smoke: validate PASS (role=%u)\n", adp[1]);
            else
                printf("[FStarExtractor] RPC smoke: validate FAIL\n");
        } else {
            printf("[FStarExtractor] RPC smoke: login FAIL\n");
        }
    }

    volatile struct ring_dataport *http_rx =
        (volatile struct ring_dataport *)proxy_in;
    volatile struct ring_dataport *http_tx =
        (volatile struct ring_dataport *)proxy_out;
    volatile struct ring_dataport *gate_tx =
        (volatile struct ring_dataport *)gate_out;
    volatile struct ring_dataport *gate_rx =
        (volatile struct ring_dataport *)gate_in;

    static uint8_t reqbuf[4096];
    uint16_t reqbuf_len = 0;

    printf("[FStarExtractor] Ready\n");

    while (1) {
        bool did_work = false;
        struct frame_entry *slot;

        /* ---- Read raw HTTP from Link 3 (LwipProxy -> FStarExtractor) ---- */
        while ((slot = ring_consume(http_rx)) != NULL) {
            uint16_t copy = slot->len;
            if (reqbuf_len + copy > sizeof(reqbuf)) {
                copy = (uint16_t)(sizeof(reqbuf) - reqbuf_len);
            }
            if (copy > 0) {
                memcpy(reqbuf + reqbuf_len, slot->data, copy);
                reqbuf_len += copy;
            }
            ring_release(http_rx);
            did_work = true;

            /* Dashboard shortcut (before extraction) */
            if (is_dashboard_request(reqbuf, reqbuf_len)) {
                write_dashboard_response(http_tx);
                to_proxy_ready_emit();
                reqbuf_len = 0;
                continue;
            }

            /* Verified extraction (F*-verified via KreMLin) */
            uint8_t wire_buf[WEB_FRAME_MTU];
            uint32_t wire_len = 0;
            uint8_t res = extract_security_params(
                reqbuf, (uint32_t)reqbuf_len, wire_buf, &wire_len);

            if (res == EXTRACT_OK) {
                SecurityParamsWire *params = (SecurityParamsWire *)wire_buf;
                uint32_t path_hash = params->path_hash;
                uint8_t method = params->method;

                /* ---- Auth routing (Phase 4) ---- */

                if (path_hash == 0) {
                    /* Unknown endpoint -> 404 */
                    write_to_ring(http_tx, (const uint8_t *)RESP_404_BODY,
                                 (uint32_t)(sizeof(RESP_404_BODY) - 1));
                    to_proxy_ready_emit();

                } else if (path_hash == PATH_LOGIN && method == METHOD_POST) {
                    /* Login: Authenticator handles directly, no PolicyGate */
                    handle_login(http_tx, params);

                } else if (path_hash == PATH_LOGOUT) {
                    /* Logout: stateless (client discards token) */
                    uint8_t resp_buf[512];
                    uint32_t resp_len = 0;
                    format_ok_json("{\"status\":\"ok\",\"message\":\"logged out\"}",
                                  resp_buf, &resp_len);
                    write_to_ring(http_tx, resp_buf, resp_len);
                    to_proxy_ready_emit();

                } else if (params->token_len == 0) {
                    /* Protected endpoint without token -> 401 */
                    uint8_t resp_buf[512];
                    uint32_t resp_len = 0;
                    format_unauthorized(resp_buf, &resp_len);
                    write_to_ring(http_tx, resp_buf, resp_len);
                    to_proxy_ready_emit();

                } else {
                    /* Protected endpoint with token -> validate, then PolicyGate */
                    int valid = validate_and_fill(wire_buf, params);
                    if (!valid) {
                        /* Bad token -> 403 */
                        uint8_t resp_buf[512];
                        uint32_t resp_len = 0;
                        format_forbidden(resp_buf, &resp_len);
                        write_to_ring(http_tx, resp_buf, resp_len);
                        to_proxy_ready_emit();
                    } else {
                        /* Token valid, role/scope/subject filled.
                         * Recompute wire_len since we modified params. */
                        wire_len = secparams_wire_size(params);
                        printf("[FStarExtractor] -> PolicyGate path=0x%08lx role=%u\n",
                               (unsigned long)path_hash, params->role);
                        write_to_ring(gate_tx, wire_buf, wire_len);
                        to_gate_ready_emit();
                    }
                }

                reqbuf_len = 0;
            } else if (res == EXTRACT_INCOMPLETE) {
                /* Keep buffering */
            } else {
                uint8_t resp_buf[512];
                uint32_t resp_len = 0;
                format_extraction_error((ExtractionResult)res, resp_buf, &resp_len);
                write_to_ring(http_tx, resp_buf, resp_len);
                to_proxy_ready_emit();
                reqbuf_len = 0;
            }
        }

        /* ---- Read GateResponse from PolicyGate (Link 4 reverse) ---- */
        while ((slot = ring_consume(gate_rx)) != NULL) {
            if (slot->len >= GATE_RESPONSE_HEADER_SIZE) {
                GateResponse *gresp = (GateResponse *)slot->data;
                uint8_t resp_buf[WEB_FRAME_MTU];
                uint32_t resp_len = 0;
                format_gate_response(gresp, resp_buf, &resp_len);
                write_to_ring(http_tx, resp_buf, resp_len);
                to_proxy_ready_emit();
            }
            ring_release(gate_rx);
            did_work = true;
        }

        if (!did_work) {
            seL4_Yield();
        }
    }

    return 0;
}
