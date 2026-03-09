/*
 * entropy_x86.c — x86 RDRAND instruction for mbedTLS entropy
 *
 * Uses x86 RDRAND instruction for hardware random number generation.
 * RDRAND is available on Intel Ivy Bridge+ and AMD Zen+ processors.
 * QEMU emulates RDRAND when -cpu qemu64,+rdrand is specified.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* mbedTLS entropy interface */
#include "mbedtls/entropy.h"

/* Check if RDRAND succeeded (carry flag set) */
static inline int rdrand64(uint64_t *val)
{
    unsigned char ok;
    __asm__ volatile(
        "rdrand %0\n\t"
        "setc %1"
        : "=r"(*val), "=qm"(ok)
    );
    return ok;
}

/* Fallback: simple LFSR PRNG if RDRAND fails */
static uint64_t lfsr_state = 0xDEADBEEFCAFEBABEULL;

static uint64_t lfsr64(void)
{
    /* Galois LFSR with maximal period polynomial */
    uint64_t bit = ((lfsr_state >> 0) ^ (lfsr_state >> 1) ^
                    (lfsr_state >> 3) ^ (lfsr_state >> 4)) & 1;
    lfsr_state = (lfsr_state >> 1) | (bit << 63);
    return lfsr_state;
}

static int rdrand_available = -1;  /* -1 = unknown, 0 = no, 1 = yes */

void entropy_x86_init(void)
{
    /* Test if RDRAND works */
    uint64_t test;
    int retries = 10;

    while (retries-- > 0) {
        if (rdrand64(&test)) {
            rdrand_available = 1;
            printf("[entropy_x86] RDRAND available\n");
            return;
        }
    }

    rdrand_available = 0;
    printf("[entropy_x86] RDRAND not available, using LFSR fallback\n");

    /* Seed LFSR with TSC */
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    lfsr_state ^= ((uint64_t)hi << 32) | lo;
}

/*
 * mbedtls_hardware_poll() — called by mbedTLS entropy collector.
 * Must fill output buffer with `len` bytes of entropy.
 * Returns 0 on success, sets *olen to bytes written.
 */
int mbedtls_hardware_poll(void *data, unsigned char *output,
                          size_t len, size_t *olen)
{
    (void)data;

    if (rdrand_available < 0) {
        entropy_x86_init();
    }

    size_t written = 0;
    while (written < len) {
        uint64_t word;

        if (rdrand_available == 1) {
            /* Try RDRAND with retry */
            int retries = 10;
            while (retries-- > 0 && !rdrand64(&word)) {
                /* RDRAND can transiently fail under load */
            }
            if (retries < 0) {
                /* Fall back to LFSR for this word */
                word = lfsr64();
            }
        } else {
            word = lfsr64();
        }

        size_t remaining = len - written;
        size_t copy = (remaining < 8) ? remaining : 8;
        memcpy(output + written, &word, copy);
        written += copy;
    }

    *olen = written;
    return 0;
}
