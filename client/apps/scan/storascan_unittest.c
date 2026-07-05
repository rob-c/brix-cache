/*
 * storascan_unittest.c — standalone suite for storascan_core (no server, no lib).
 *
 *   gcc -Wall -Wextra -Werror -o /tmp/storascan_ut \
 *       client/apps/storascan_unittest.c client/apps/storascan_core.c -lm \
 *       && /tmp/storascan_ut
 *
 * Exit 0 = all checks pass. Driven by tests/test_storascan.py.
 */
#include "storascan_core.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int g_fail;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);  \
            g_fail++;                                                          \
        }                                                                      \
    } while (0)

#define CLOSE(a, b) (fabs((a) - (b)) < 1e-6)

static void
test_cks_compare(void)
{
    CHECK(storascan_cks_compare("a1b2c3d4", "a1b2c3d4") == STORASCAN_CKS_MATCH,
          "identical digests match");
    /* case-insensitive */
    CHECK(storascan_cks_compare("A1B2C3D4", "a1b2c3d4") == STORASCAN_CKS_MATCH,
          "case-insensitive match");
    /* surrounding whitespace ignored */
    CHECK(storascan_cks_compare("a1b2c3d4", "  a1b2c3d4\n") == STORASCAN_CKS_MATCH,
          "trims surrounding whitespace");
    CHECK(storascan_cks_compare("a1b2c3d4", "deadbeef") == STORASCAN_CKS_MISMATCH,
          "different digests mismatch");
    CHECK(storascan_cks_compare("a1b2c3d4", NULL) == STORASCAN_CKS_MISSING,
          "NULL stored is missing");
    CHECK(storascan_cks_compare("a1b2c3d4", "") == STORASCAN_CKS_MISSING,
          "empty stored is missing");
    CHECK(storascan_cks_compare("a1b2c3d4", "   ") == STORASCAN_CKS_MISSING,
          "whitespace-only stored is missing");
}

static void
test_percentile(void)
{
    double s10[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    /* nearest-rank: p50 of 1..10 -> rank ceil(0.5*10)=5 -> value 5 */
    CHECK(CLOSE(storascan_percentile_ms(s10, 10, 50), 5.0), "p50 of 1..10 == 5");
    /* p95 -> rank ceil(9.5)=10 -> value 10 */
    CHECK(CLOSE(storascan_percentile_ms(s10, 10, 95), 10.0), "p95 of 1..10 == 10");
    /* p99 -> rank ceil(9.9)=10 -> value 10 */
    CHECK(CLOSE(storascan_percentile_ms(s10, 10, 99), 10.0), "p99 of 1..10 == 10");
    /* p0/min edge -> rank ceil(0)=0 -> clamp to first element */
    CHECK(CLOSE(storascan_percentile_ms(s10, 10, 0), 1.0), "p0 -> min");
    /* empty -> 0 */
    CHECK(CLOSE(storascan_percentile_ms(s10, 0, 50), 0.0), "empty -> 0");

    {
        double one[1] = {42.0};
        CHECK(CLOSE(storascan_percentile_ms(one, 1, 99), 42.0), "single sample");
    }
}

static void
test_bench_compute(void)
{
    /* Unsorted input: must be sorted internally without mutating the caller. */
    double lat[5] = {10.0, 2.0, 8.0, 4.0, 6.0};
    double lat_copy[5];
    storascan_bench_result r;

    memcpy(lat_copy, lat, sizeof(lat));

    /* 5 ops, 50 MiB total, in 2.0 s */
    storascan_bench_compute(lat, 5, 50ull << 20, 2.0, &r);

    CHECK(r.ops == 5, "ops counted");
    CHECK(r.bytes == (50ull << 20), "bytes carried");
    CHECK(CLOSE(r.elapsed_s, 2.0), "elapsed carried");
    /* 50 MiB / 2 s = 25 MiB/s */
    CHECK(CLOSE(r.throughput_mibps, 25.0), "throughput 25 MiB/s");
    /* 5 ops / 2 s = 2.5 iops */
    CHECK(CLOSE(r.iops, 2.5), "iops 2.5");
    /* sorted 2,4,6,8,10 -> p50 rank ceil(2.5)=3 -> 6 */
    CHECK(CLOSE(r.p50_ms, 6.0), "bench p50 == 6");
    /* input array left untouched */
    CHECK(memcmp(lat, lat_copy, sizeof(lat)) == 0, "input array not mutated");

    /* zero elapsed -> throughput/iops 0, no div-by-zero */
    storascan_bench_compute(lat, 5, 50ull << 20, 0.0, &r);
    CHECK(CLOSE(r.throughput_mibps, 0.0), "zero elapsed -> 0 throughput");
    CHECK(CLOSE(r.iops, 0.0), "zero elapsed -> 0 iops");
}

int
main(void)
{
    test_cks_compare();
    test_percentile();
    test_bench_compute();

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("storascan_core: all checks passed\n");
    return 0;
}
