/*
 * PolicyGate.c -- CAmkES component: pure PDP + PAP (Phase 4)
 *
 * Receives SecurityParamsWire from FStarExtractor (Link 4 forward ring).
 * Role/scope arrive pre-resolved from Authenticator (no session table).
 * Runs EverParse validation. If authorized, forwards AppRequest to
 * ProtectedApp (Link 5). Reads AppResponse and relays as GateResponse
 * back to FStarExtractor (Link 4 reverse).
 *
 * No sessions, no credentials, no login handling.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <camkes.h>
#include <sel4/sel4.h>

#include "web_common.h"
#include "security_params_wire.h"
#include "gate_response_wire.h"
#include "app_wire.h"
#include "control_pipeline.h"

/* ------------------------------------------------------------------ */
/* Main loop                                                          */
/* ------------------------------------------------------------------ */

static Policy policy;

int run(void)
{
    printf("[PolicyGate] Starting (pure PDP, Phase 4)\n");

    policy_init_default(&policy);
    printf("[PolicyGate] Pipeline initialized: %d default rules\n",
           policy.num_rules);

    volatile struct ring_dataport *ext_rx =
        (volatile struct ring_dataport *)ext_in;
    volatile struct ring_dataport *ext_tx =
        (volatile struct ring_dataport *)ext_out;
    volatile struct ring_dataport *app_tx =
        (volatile struct ring_dataport *)app_out;
    volatile struct ring_dataport *app_rx =
        (volatile struct ring_dataport *)app_in;

    printf("[PolicyGate] Ready\n");

    while (1) {
        bool did_work = false;
        struct frame_entry *slot;

        /* ---- Read SecurityParamsWire from FStarExtractor (Link 4 forward) ---- */
        while ((slot = ring_consume(ext_rx)) != NULL) {
            if (slot->len >= SECPARAMS_HEADER_SIZE) {
                SecurityParamsWire *params = (SecurityParamsWire *)slot->data;

                static uint8_t gate_buf[WEB_FRAME_MTU];
                static uint8_t app_buf[WEB_FRAME_MTU];
                uint32_t gate_len = 0;
                uint32_t app_len = 0;

                int result = pipeline_process(&policy, params,
                                               gate_buf, &gate_len,
                                               app_buf, &app_len);

                if (result == PIPELINE_FORWARD) {
                    /* Authorized: forward AppRequest to ProtectedApp (Link 5) */
                    struct frame_entry *out = ring_produce(app_tx);
                    if (out) {
                        out->len = (uint16_t)app_len;
                        memcpy(out->data, app_buf, app_len);
                        ring_commit(app_tx);
                        to_app_ready_emit();
                    } else {
                        printf("[PolicyGate] WARN: app ring full\n");
                    }
                } else {
                    /* Denied or policy update: send GateResponse to FStarExtractor */
                    if (gate_len > 0) {
                        struct frame_entry *out = ring_produce(ext_tx);
                        if (out) {
                            out->len = (uint16_t)gate_len;
                            memcpy(out->data, gate_buf, gate_len);
                            ring_commit(ext_tx);
                            to_ext_ready_emit();
                        } else {
                            printf("[PolicyGate] WARN: ext ring full\n");
                        }
                    }
                }
            }
            ring_release(ext_rx);
            did_work = true;
        }

        /* ---- Read AppResponse from ProtectedApp (Link 5 reverse) ---- */
        while ((slot = ring_consume(app_rx)) != NULL) {
            if (slot->len >= APP_RESPONSE_HEADER_SIZE) {
                /* Relay AppResponse as GateResponse to FStarExtractor.
                 * AppResponse and GateResponse have the same layout. */
                struct frame_entry *out = ring_produce(ext_tx);
                if (out) {
                    out->len = slot->len;
                    memcpy(out->data, slot->data, slot->len);
                    ring_commit(ext_tx);
                    to_ext_ready_emit();
                } else {
                    printf("[PolicyGate] WARN: ext ring full (relay)\n");
                }
            }
            ring_release(app_rx);
            did_work = true;
        }

        if (!did_work) {
            seL4_Yield();
        }
    }

    return 0;
}
