/*
 * B1: Bitmask Operations — Test Harness
 *
 * Three variants:
 *   A: Full bitmask with shift — (allowed_mask & (1ul << fc)) != 0
 *   B: Pre-shifted bit          — (allowed_mask & fc_bit) != 0
 *   C: Minimal bitwise AND      — (a & b) != 0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "generated/BitTestAWrapper.h"
#include "generated/BitTestBWrapper.h"
#include "generated/BitTestCWrapper.h"

void BitTestAEverParseError(const char *s, const char *f, const char *r) {
    (void)s; (void)f; (void)r;
}
void BitTestBEverParseError(const char *s, const char *f, const char *r) {
    (void)s; (void)f; (void)r;
}
void BitTestCEverParseError(const char *s, const char *f, const char *r) {
    (void)s; (void)f; (void)r;
}

static void write_u32le(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

static int passed = 0, failed = 0;

static void check(const char *name, int expect, BOOLEAN got) {
    int g = got ? 1 : 0;
    if (g == expect) {
        printf("  PASS  %s\n", name);
        passed++;
    } else {
        printf("  FAIL  %s  (expected %s, got %s)\n", name,
               expect ? "ACCEPT" : "REJECT", g ? "ACCEPT" : "REJECT");
        failed++;
    }
}

/* === Variant A: [allowed_mask:u32le][fc:u8][_guard:u8][_check:u8] = 7 bytes === */
static void test_A(const char *name, int expect, uint32_t mask, uint8_t fc) {
    uint8_t buf[7];
    write_u32le(buf, mask);
    buf[4] = fc;
    buf[5] = 0;  /* _guard */
    buf[6] = 0;  /* _check */
    check(name, expect, BitTestACheckBitTestA(buf, sizeof(buf)));
}

/* === Variant B: [allowed_mask:u32le][fc_bit:u32le][_check:u8] = 9 bytes === */
static void test_B(const char *name, int expect, uint32_t mask, uint32_t fc_bit) {
    uint8_t buf[9];
    write_u32le(buf, mask);
    write_u32le(buf + 4, fc_bit);
    buf[8] = 0;  /* _check */
    check(name, expect, BitTestBCheckBitTestB(buf, sizeof(buf)));
}

/* === Variant C: [a:u32le][b:u32le][_check:u8] = 9 bytes === */
static void test_C(const char *name, int expect, uint32_t a, uint32_t b) {
    uint8_t buf[9];
    write_u32le(buf, a);
    write_u32le(buf + 4, b);
    buf[8] = 0;  /* _check */
    check(name, expect, BitTestCCheckBitTestC(buf, sizeof(buf)));
}

int main(void)
{
    printf("=== B1: Bitmask Operations ===\n\n");

    /* --- Variant A: Full shift-based bitmask --- */
    /* allowed_mask = 0x1A = bits {1,3,4} → allows FC 1, 3, 4 */
    printf("--- Variant A: (allowed_mask & (1 << fc)) != 0 ---\n");
    test_A("A1: mask=0x1A, fc=3 (bit 3 set)",   1, 0x1A, 3);
    test_A("A2: mask=0x1A, fc=5 (bit 5 clear)",  0, 0x1A, 5);
    test_A("A3: mask=0x1A, fc=1 (bit 1 set)",   1, 0x1A, 1);
    test_A("A4: mask=0x00, fc=1 (nothing set)",  0, 0x00, 1);
    test_A("A5: mask=0xFF, fc=7 (all set)",      1, 0xFF, 7);
    test_A("A6: mask=0x80000000, fc=31 (bit 31)", 1, 0x80000000u, 31);
    test_A("A7: mask=0x1A, fc=0 (bit 0 clear)",  0, 0x1A, 0);

    /* --- Variant B: Pre-shifted bit --- */
    printf("\n--- Variant B: (allowed_mask & fc_bit) != 0 ---\n");
    test_B("B1: mask=0x1A, fc_bit=0x08 (1<<3)", 1, 0x1A, 0x08);
    test_B("B2: mask=0x1A, fc_bit=0x20 (1<<5)", 0, 0x1A, 0x20);
    test_B("B3: mask=0x1A, fc_bit=0x02 (1<<1)", 1, 0x1A, 0x02);
    test_B("B4: mask=0x00, fc_bit=0x02",         0, 0x00, 0x02);
    test_B("B5: mask=0xFF, fc_bit=0x80",          1, 0xFF, 0x80);

    /* --- Variant C: Raw bitwise AND --- */
    printf("\n--- Variant C: (a & b) != 0 ---\n");
    test_C("C1: a=0xFF, b=0x01 (overlap)",    1, 0xFF, 0x01);
    test_C("C2: a=0xF0, b=0x0F (no overlap)", 0, 0xF0, 0x0F);
    test_C("C3: a=0x00, b=0xFF (a empty)",    0, 0x00, 0xFF);
    test_C("C4: a=0xDEADBEEF, b=0x00000001",  1, 0xDEADBEEF, 0x01);
    test_C("C5: a=0xAAAAAAAA, b=0x55555555",  0, 0xAAAAAAAA, 0x55555555);

    printf("\n=== Results: %d/%d passed ===\n", passed, passed + failed);
    return failed > 0 ? 1 : 0;
}
