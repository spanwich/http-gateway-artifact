/*
 * B2: Arithmetic Expressions — Test Harness
 *
 * Tests multiplication, addition, subtraction (U8 and U16), and
 * combined Modbus-realistic checks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "generated/ArithMulWrapper.h"
#include "generated/ArithAddWrapper.h"
#include "generated/SubTestWrapper.h"
#include "generated/SubTest16Wrapper.h"
#include "generated/ModbusCheckWrapper.h"

/* Error callbacks (one per module) */
void ArithMulEverParseError(const char *s, const char *f, const char *r) {
    (void)s; (void)f; (void)r;
}
void ArithAddEverParseError(const char *s, const char *f, const char *r) {
    (void)s; (void)f; (void)r;
}
void SubTestEverParseError(const char *s, const char *f, const char *r) {
    (void)s; (void)f; (void)r;
}
void SubTest16EverParseError(const char *s, const char *f, const char *r) {
    (void)s; (void)f; (void)r;
}
void ModbusCheckEverParseError(const char *s, const char *f, const char *r) {
    (void)s; (void)f; (void)r;
}

static void write_u16le(uint8_t *buf, uint16_t val) {
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
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

/* ========== ArithMul: [quantity:u16le][byte_count:u8][_guard:u8][_check:u8] = 5 bytes ========== */
static void test_mul(const char *name, int expect, uint16_t quantity, uint8_t byte_count) {
    uint8_t buf[5];
    write_u16le(buf, quantity);
    buf[2] = byte_count;
    buf[3] = 0;  /* _guard placeholder */
    buf[4] = 0;  /* _check placeholder */
    check(name, expect, ArithMulCheckArithMul(buf, sizeof(buf)));
}

/* ========== ArithAdd: [a:u16le][b:u16le][expected_sum:u16le][_guard:u8][_check:u8] = 8 bytes ========== */
static void test_add(const char *name, int expect, uint16_t a, uint16_t b, uint16_t expected_sum) {
    uint8_t buf[8];
    write_u16le(buf, a);
    write_u16le(buf + 2, b);
    write_u16le(buf + 4, expected_sum);
    buf[6] = 0;  /* _guard placeholder */
    buf[7] = 0;  /* _check placeholder */
    check(name, expect, ArithAddCheckArithAdd(buf, sizeof(buf)));
}

/* ========== SubTestU8: [a:u8][b:u8][expected:u8][_guard:u8][_check:u8] = 5 bytes ========== */
static void test_sub8(const char *name, int expect, uint8_t a, uint8_t b, uint8_t expected) {
    uint8_t buf[5];
    buf[0] = a;
    buf[1] = b;
    buf[2] = expected;
    buf[3] = 0;  /* _guard placeholder */
    buf[4] = 0;  /* _check placeholder */
    check(name, expect, SubTestCheckSubTestU8(buf, sizeof(buf)));
}

/* ========== SubTest16: [msg_total:u16le][msg_header:u16le][expected_body:u16le][_guard:u8][_check:u8] = 8 bytes ========== */
static void test_sub16(const char *name, int expect, uint16_t msg_total, uint16_t msg_header, uint16_t expected_body) {
    uint8_t buf[8];
    write_u16le(buf, msg_total);
    write_u16le(buf + 2, msg_header);
    write_u16le(buf + 4, expected_body);
    buf[6] = 0;  /* _guard placeholder */
    buf[7] = 0;  /* _check placeholder */
    check(name, expect, SubTest16CheckSubTest16(buf, sizeof(buf)));
}

/* ========== ModbusCheck: [fc:u8][start_address:u16le][quantity:u16le][byte_count:u8][_bounds:u8][_check:u8] = 8 bytes ========== */
static void test_modbus(const char *name, int expect,
                        uint8_t fc, uint16_t start_addr, uint16_t quantity, uint8_t byte_count) {
    uint8_t buf[8];
    buf[0] = fc;
    write_u16le(buf + 1, start_addr);
    write_u16le(buf + 3, quantity);
    buf[5] = byte_count;
    buf[6] = 0;  /* _bounds placeholder */
    buf[7] = 0;  /* _check placeholder */
    check(name, expect, ModbusCheckCheckModbusCheck(buf, sizeof(buf)));
}

int main(void)
{
    printf("=== B2: Arithmetic Expressions ===\n\n");

    /* --- Multiplication --- */
    printf("--- Multiplication (byte_count == quantity * 2) ---\n");
    test_mul("T1: q=10,bc=20 (20==10*2)",   1, 10, 20);
    test_mul("T2: q=10,bc=19 (19!=10*2)",    0, 10, 19);
    test_mul("T3: q=0,bc=0   (0==0*2)",      1, 0, 0);
    test_mul("T4: q=125,bc=250 (250==125*2)", 1, 125, 250);
    test_mul("T5: q=1,bc=2   (2==1*2)",      1, 1, 2);

    /* --- Addition --- */
    printf("\n--- Addition (expected_sum == a + b) ---\n");
    test_add("T6: a=100,b=200,s=300",    1, 100, 200, 300);
    test_add("T7: a=100,b=200,s=301",    0, 100, 200, 301);
    test_add("T8: a=0,b=0,s=0",          1, 0, 0, 0);
    test_add("T9: a=30000,b=30000,s=60000", 1, 30000, 30000, 60000);
    test_add("T10: a=1,b=65534,s=65535",  0, 1, 65534, 65535); /* a ok but b > 30000 → guard fails */

    /* --- Subtraction (U8) --- */
    printf("\n--- Subtraction U8 (expected == a - b) ---\n");
    test_sub8("T11: a=10,b=3,e=7",   1, 10, 3, 7);
    test_sub8("T12: a=10,b=3,e=8",   0, 10, 3, 8);
    test_sub8("T13: a=0,b=0,e=0",    1, 0, 0, 0);
    test_sub8("T14: a=255,b=1,e=254", 1, 255, 1, 254);
    test_sub8("T15: a=3,b=10,e=0",   0, 3, 10, 0); /* underflow guard: a < b → REJECT */

    /* --- Subtraction (U16) --- */
    printf("\n--- Subtraction U16 (expected_body == msg_total - msg_header) ---\n");
    test_sub16("T16: t=1000,h=400,e=600",  1, 1000, 400, 600);
    test_sub16("T17: t=1000,h=400,e=601",  0, 1000, 400, 601);
    test_sub16("T18: t=0,h=0,e=0",         1, 0, 0, 0);
    test_sub16("T19: t=65535,h=1,e=65534",  1, 65535, 1, 65534);
    test_sub16("T20: t=100,h=200,e=0",     0, 100, 200, 0); /* underflow guard: t < h → REJECT */

    /* --- Modbus Combined --- */
    printf("\n--- Modbus FC3 Combined (fc==3, bc==q*2, q in [1..125], addr+q<=65535) ---\n");
    test_modbus("T21: fc=3,addr=0,q=10,bc=20",     1, 3, 0, 10, 20);
    test_modbus("T22: fc=3,addr=0,q=10,bc=21",     0, 3, 0, 10, 21);    /* wrong byte_count */
    test_modbus("T23: fc=3,addr=0,q=0,bc=0",       0, 3, 0, 0, 0);      /* quantity < 1 */
    test_modbus("T24: fc=3,addr=0,q=126,bc=252",   0, 3, 0, 126, 252);  /* quantity > 125 */
    test_modbus("T25: fc=3,addr=65530,q=10,bc=20",  0, 3, 65530, 10, 20); /* addr+q > 65535 */
    test_modbus("T26: fc=4,addr=0,q=10,bc=20",     0, 4, 0, 10, 20);    /* fc != 3 */
    test_modbus("T27: fc=3,addr=100,q=125,bc=250",  1, 3, 100, 125, 250); /* max valid */
    test_modbus("T28: fc=3,addr=65410,q=125,bc=250", 1, 3, 65410, 125, 250); /* boundary: 65410+125=65535 */

    printf("\n=== Results: %d/%d passed ===\n", passed, passed + failed);
    return failed > 0 ? 1 : 0;
}
