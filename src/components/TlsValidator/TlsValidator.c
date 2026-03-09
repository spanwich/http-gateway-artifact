/*
 * TlsValidator.c — Bidirectional frame passthrough (no-op)
 *
 * Forwards frames between E1000Driver and LwipProxy in both directions
 * using ring buffer dataports. Drains all available frames each direction.
 * Future: EverParse TLS record-layer validation.
 *
 * x86 port from BCM2837 TlsValidator.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <camkes.h>
#include <sel4/sel4.h>

#include "web_common.h"

/* Diagnostic counters */
static uint32_t g_tv_fwd = 0;      /* Forward: E1000Driver -> LwipProxy */
static uint32_t g_tv_rev = 0;      /* Reverse: LwipProxy -> E1000Driver */
static uint32_t g_tv_fwd_full = 0; /* Forward ring full */
static uint32_t g_tv_rev_full = 0; /* Reverse ring full */
static uint32_t g_tv_loops = 0;    /* Main loop iterations */
static uint32_t g_last_fwd = 0;
static uint32_t g_last_rev = 0;

int run(void)
{
    printf("[TlsValidator] x86 passthrough ready (no-op)\n");

    volatile struct ring_dataport *drv_rx  = (volatile struct ring_dataport *)drv_in;
    volatile struct ring_dataport *prx_tx  = (volatile struct ring_dataport *)proxy_out;
    volatile struct ring_dataport *prx_rx  = (volatile struct ring_dataport *)proxy_in;
    volatile struct ring_dataport *drv_tx  = (volatile struct ring_dataport *)drv_out;

    while (1) {
        bool did_work = false;
        g_tv_loops++;

        /* Periodic status print every ~100000 loops */
        if (g_tv_loops % 100000 == 0) {
            printf("[TV] f:%lu r:%lu bf:%lu br:%lu pout_h=%u pout_t=%u pout_p=%p\n",
                   (unsigned long)(g_tv_fwd - g_last_fwd),
                   (unsigned long)(g_tv_rev - g_last_rev),
                   (unsigned long)g_tv_fwd_full,
                   (unsigned long)g_tv_rev_full,
                   prx_tx->head, prx_tx->tail, (void *)prx_tx);
            g_last_fwd = g_tv_fwd;
            g_last_rev = g_tv_rev;
        }

        /* Forward: E1000Driver -> LwipProxy */
        struct frame_entry *src;
        while ((src = ring_consume(drv_rx)) != NULL) {
            struct frame_entry *dst = ring_produce(prx_tx);
            if (!dst) {
                g_tv_fwd_full++;
                break;  /* Downstream full - leave frame for next cycle */
            }
            dst->len = src->len;
            memcpy(dst->data, src->data, src->len);
            ring_release(drv_rx);
            ring_commit(prx_tx);
            to_proxy_ready_emit();
            g_tv_fwd++;
            did_work = true;
        }

        /* Reverse: LwipProxy -> E1000Driver */
        while ((src = ring_consume(prx_rx)) != NULL) {
            struct frame_entry *dst = ring_produce(drv_tx);
            if (!dst) {
                g_tv_rev_full++;
                break;
            }
            dst->len = src->len;
            memcpy(dst->data, src->data, src->len);
            ring_release(prx_rx);
            ring_commit(drv_tx);
            to_drv_ready_emit();
            g_tv_rev++;
            did_work = true;
        }

        if (!did_work) {
            seL4_Yield();
        }
    }

    return 0;
}
