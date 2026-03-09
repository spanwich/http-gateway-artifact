/*
 * Test harness for F*-verified parse_method
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "HTTP_Extract_Method.h"

static int pass = 0, total = 0;

#define TEST(name, input, ilen, exp_code, exp_end) do { \
    total++; \
    method_result r = parse_method((uint8_t *)(input), (ilen)); \
    if (r.mr_code == (exp_code) && r.mr_end == (exp_end)) { \
        printf("  PASS: %s (code=%u end=%u)\n", (name), r.mr_code, r.mr_end); \
        pass++; \
    } else { \
        printf("  FAIL: %s (expected code=%u end=%u, got code=%u end=%u)\n", \
               (name), (uint8_t)(exp_code), (uint32_t)(exp_end), r.mr_code, r.mr_end); \
    } \
} while(0)

int main(void)
{
    printf("=== parse_method test suite ===\n\n");

    /* Recognized methods */
    TEST("GET request",  "GET / HTTP/1.1\r\n", 16, 1, 4);
    TEST("POST request", "POST /api/login HTTP/1.1\r\n", 26, 2, 5);
    TEST("PUT request",  "PUT /api/policy HTTP/1.1\r\n", 26, 3, 4);

    /* Minimum valid */
    TEST("GET minimal",  "GET ", 4, 1, 4);
    TEST("PUT minimal",  "PUT ", 4, 3, 4);
    TEST("POST minimal", "POST ", 5, 2, 5);

    /* Unknown methods */
    TEST("DELETE",  "DELETE /foo HTTP/1.1", 20, 0, 0);
    TEST("HEAD",    "HEAD / HTTP/1.1", 16, 0, 0);
    TEST("PATCH",   "PATCH /foo HTTP/1.1", 19, 0, 0);
    TEST("OPTIONS", "OPTIONS * HTTP/1.1", 18, 0, 0);

    /* Too short */
    TEST("empty",    "", 0, 0, 0);
    TEST("1 byte",   "G", 1, 0, 0);
    TEST("2 bytes",  "GE", 2, 0, 0);
    TEST("3 bytes",  "GET", 3, 0, 0);

    /* Edge: POST without 5th byte */
    TEST("POST no space (4 bytes)", "POST", 4, 0, 0);

    /* Case sensitivity */
    TEST("get lowercase", "get / HTTP/1.1", 14, 0, 0);
    TEST("Get mixed",     "Get / HTTP/1.1", 14, 0, 0);

    printf("\n=== Results: %d/%d passed ===\n", pass, total);
    return (pass == total) ? 0 : 1;
}
