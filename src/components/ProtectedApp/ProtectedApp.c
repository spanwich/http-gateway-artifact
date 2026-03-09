/*
 * ProtectedApp.c -- CAmkES component: resource server (Phase 4)
 *
 * Receives authorized AppRequests from PolicyGate (Link 5 forward).
 * Dispatches by path_hash and produces AppResponses.
 *
 * This component has ZERO auth/crypto awareness.
 * PolicyGate has already verified the request is authorized.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <camkes.h>
#include <sel4/sel4.h>

#include "web_common.h"
#include "app_wire.h"
#include "path_hashes.h"

static const char *role_name(uint8_t role)
{
    switch (role) {
    case ROLE_NONE:     return "NONE";
    case ROLE_OPERATOR: return "OPERATOR";
    case ROLE_ADMIN:    return "ADMIN";
    default:            return "UNKNOWN";
    }
}

static uint32_t make_app_response(uint8_t *buf, uint8_t conn_id,
                                   uint8_t status, const char *json)
{
    AppResponse *resp = (AppResponse *)buf;
    resp->conn_id = conn_id;
    resp->status = status;
    if (json) {
        uint32_t blen = (uint32_t)strlen(json);
        resp->body_len = blen;
        memcpy(resp->body, json, blen);
        return APP_RESPONSE_HEADER_SIZE + blen;
    } else {
        resp->body_len = 0;
        return APP_RESPONSE_HEADER_SIZE;
    }
}

static uint32_t handle_status(const AppRequest *req, uint8_t *resp_buf)
{
    char body[128];
    snprintf(body, sizeof(body),
             "{\"status\":\"ok\",\"role\":\"%s\"}", role_name(req->role));
    return make_app_response(resp_buf, req->conn_id, 1, body);
}

static uint32_t handle_policy_get(const AppRequest *req, uint8_t *resp_buf)
{
    return make_app_response(resp_buf, req->conn_id, 1,
        "{\"status\":\"ok\",\"message\":\"policy read ok\"}");
}

static uint32_t handle_default(const AppRequest *req, uint8_t *resp_buf)
{
    return make_app_response(resp_buf, req->conn_id, 1,
        "{\"status\":\"ok\"}");
}

int run(void)
{
    printf("[ProtectedApp] Starting (resource server)\n");

    volatile struct ring_dataport *rx =
        (volatile struct ring_dataport *)gate_in;
    volatile struct ring_dataport *tx =
        (volatile struct ring_dataport *)gate_out;

    printf("[ProtectedApp] Ready\n");

    while (1) {
        bool did_work = false;
        struct frame_entry *slot;

        while ((slot = ring_consume(rx)) != NULL) {
            if (slot->len >= APP_REQUEST_HEADER_SIZE) {
                AppRequest *req = (AppRequest *)slot->data;

                printf("[ProtectedApp] path=0x%08lx method=%u role=%s\n",
                       (unsigned long)req->path_hash,
                       req->method, role_name(req->role));

                static uint8_t resp_buf[WEB_FRAME_MTU];
                uint32_t resp_len = 0;

                if (req->path_hash == PATH_STATUS && req->method == METHOD_GET) {
                    resp_len = handle_status(req, resp_buf);
                } else if (req->path_hash == PATH_POLICY && req->method == METHOD_GET) {
                    resp_len = handle_policy_get(req, resp_buf);
                } else {
                    resp_len = handle_default(req, resp_buf);
                }

                if (resp_len > 0) {
                    struct frame_entry *out_slot = ring_produce(tx);
                    if (out_slot) {
                        out_slot->len = (uint16_t)resp_len;
                        memcpy(out_slot->data, resp_buf, resp_len);
                        ring_commit(tx);
                        to_gate_ready_emit();
                    } else {
                        printf("[ProtectedApp] WARN: response ring full\n");
                    }
                }
            }
            ring_release(rx);
            did_work = true;
        }

        if (!did_work) {
            seL4_Yield();
        }
    }

    return 0;
}
