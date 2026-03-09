/*
 * B3: Parameterized Range Checks — Test Harness
 *
 * Buffer layout (10 bytes):
 *   [allowed_min:u16le][allowed_max:u16le][max_rate:u8]
 *   [address:u16le][rate_count:u8]
 *   [_range_ok:u8][_rate_ok:u8]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "generated/RangeTestWrapper.h"

void RangeTestEverParseError(const char *StructName,
                             const char *FieldName,
                             const char *Reason)
{
    /* silent — test harness checks return value */
    (void)StructName;
    (void)FieldName;
    (void)Reason;
}

static void write_u16le(uint8_t *buf, uint16_t val) {
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
}

/*
 * Build a RangeCheck buffer.
 * Returns buffer size (always 10).
 */
static int build_range_buf(uint8_t *buf,
                           uint16_t allowed_min, uint16_t allowed_max,
                           uint8_t max_rate,
                           uint16_t address, uint8_t rate_count)
{
    write_u16le(buf + 0, allowed_min);
    write_u16le(buf + 2, allowed_max);
    buf[4] = max_rate;
    write_u16le(buf + 5, address);
    buf[7] = rate_count;
    buf[8] = 0;  /* _range_ok placeholder */
    buf[9] = 0;  /* _rate_ok placeholder */
    return 10;
}

static int passed = 0, failed = 0;

static void run_test(const char *name, int expect_accept,
                     uint16_t allowed_min, uint16_t allowed_max,
                     uint8_t max_rate,
                     uint16_t address, uint8_t rate_count)
{
    uint8_t buf[10];
    int len = build_range_buf(buf, allowed_min, allowed_max,
                              max_rate, address, rate_count);

    BOOLEAN result = RangeTestCheckRangeCheck(buf, (uint32_t)len);
    int got = result ? 1 : 0;

    if (got == expect_accept) {
        printf("  PASS  %s\n", name);
        passed++;
    } else {
        printf("  FAIL  %s  (expected %s, got %s)\n",
               name,
               expect_accept ? "ACCEPT" : "REJECT",
               got ? "ACCEPT" : "REJECT");
        failed++;
    }
}

int main(void)
{
    printf("=== B3: Parameterized Range Checks ===\n\n");

    /* Policy A: allowed_min=100, allowed_max=200, max_rate=10 */
    printf("Policy A: min=100, max=200, max_rate=10\n");
    run_test("T1:  addr=150, rate=5  (in range, rate ok)",
             1, 100, 200, 10, 150, 5);
    run_test("T2:  addr=99,  rate=5  (below min)",
             0, 100, 200, 10, 99, 5);
    run_test("T3:  addr=201, rate=5  (above max)",
             0, 100, 200, 10, 201, 5);
    run_test("T4:  addr=100, rate=5  (exactly min)",
             1, 100, 200, 10, 100, 5);
    run_test("T5:  addr=200, rate=5  (exactly max)",
             1, 100, 200, 10, 200, 5);
    run_test("T6:  addr=150, rate=15 (rate exceeded)",
             0, 100, 200, 10, 150, 15);
    run_test("T7:  addr=0,   rate=5  (below min)",
             0, 100, 200, 10, 0, 5);
    run_test("T8:  addr=65535,rate=5 (above max)",
             0, 100, 200, 10, 65535, 5);

    /* Policy B: full range allowed */
    printf("\nPolicy B: min=0, max=65535, max_rate=10\n");
    run_test("T9:  addr=0,     rate=5  (full range allowed)",
             1, 0, 65535, 10, 0, 5);
    run_test("T10: addr=65535, rate=5  (full range allowed)",
             1, 0, 65535, 10, 65535, 5);

    /* Policy C: single address allowed */
    printf("\nPolicy C: min=500, max=500, max_rate=10\n");
    run_test("T11: addr=500, rate=5  (single addr allowed)",
             1, 500, 500, 10, 500, 5);
    run_test("T12: addr=499, rate=5  (below single addr)",
             0, 500, 500, 10, 499, 5);
    run_test("T13: addr=501, rate=5  (above single addr)",
             0, 500, 500, 10, 501, 5);

    printf("\n=== Results: %d/%d passed ===\n", passed, passed + failed);
    return failed > 0 ? 1 : 0;
}
