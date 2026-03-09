/*
 * web_common.h — Shared ring buffer dataport protocol for 5-component web gateway
 *
 * SPSC (single-producer single-consumer) lock-free ring buffer.
 * Producer writes frame -> commit (advances head).
 * Consumer reads frame -> release (advances tail).
 * SMP-safe with memory barriers (portable via __sync_synchronize).
 *
 * x86 Note: __sync_synchronize() compiles to MFENCE on x86.
 * x86 TSO memory model makes most barriers no-ops, but we keep them
 * for correctness and portability.
 */

#ifndef WEB_COMMON_H
#define WEB_COMMON_H

#include <stdint.h>

#define WEB_FRAME_MTU 1536

#define RING_SLOTS 4           /* Must be power of 2 */
#define RING_MASK  (RING_SLOTS - 1)

struct frame_entry {
    uint16_t len;
    uint8_t  data[WEB_FRAME_MTU];
};

struct ring_dataport {
    volatile uint32_t head;                /* Written by producer */
    volatile uint32_t tail;                /* Written by consumer */
    struct frame_entry frames[RING_SLOTS]; /* 4 x 1538 = 6152 bytes */
};

/* --- Lock-free SPSC ring operations --- */

static inline int ring_full(volatile struct ring_dataport *r)
{
    return ((r->head + 1) & RING_MASK) == r->tail;
}

static inline int ring_empty(volatile struct ring_dataport *r)
{
    return r->head == r->tail;
}

static inline uint32_t ring_count(volatile struct ring_dataport *r)
{
    return (r->head - r->tail) & RING_MASK;
}

static inline struct frame_entry *ring_produce(volatile struct ring_dataport *r)
{
    if (ring_full(r)) return NULL;
    return (struct frame_entry *)&r->frames[r->head & RING_MASK];
}

static inline void ring_commit(volatile struct ring_dataport *r)
{
    __sync_synchronize();
    r->head = (r->head + 1) & RING_MASK;
}

static inline struct frame_entry *ring_consume(volatile struct ring_dataport *r)
{
    if (ring_empty(r)) return NULL;
    __sync_synchronize();
    return (struct frame_entry *)&r->frames[r->tail & RING_MASK];
}

static inline void ring_release(volatile struct ring_dataport *r)
{
    __sync_synchronize();  /* Ensure frame reads complete before tail update */
    r->tail = (r->tail + 1) & RING_MASK;
}

#endif /* WEB_COMMON_H */
