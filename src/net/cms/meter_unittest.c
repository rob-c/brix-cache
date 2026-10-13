/*
 * meter_unittest.c — standalone unit test for the CMS load meter (Phase-89 W4).
 *
 *   gcc -Wall -Wextra -Werror -I src -I src/net/cms \
 *       -DBRIX_PLATFORM_HOST=darwin -DBRIX_PLATFORM_DARWIN=1 \
 *       -DBRIX_PLATFORM_LINUX=0 -DBRIX_PLATFORM_WINDOWS=0 \
 *       -o /tmp/cms_meter_ut \
 *       src/net/cms/meter_unittest.c src/net/cms/meter.c && /tmp/cms_meter_ut
 *
 * Exit 0 = all checks pass. No nginx dependency (meter.c is pure C).
 */

#include "meter.h"
#include "platform/platform_api.h"

#include <stdio.h>
#include <string.h>

/* The standalone test does not link a host PAL. This deterministic sample
 * pins the portable CMS conversion and delta logic independently of host load. */
int brix_plat_cpu_count(void) { return 4; }
int
brix_plat_sysload_sample(brix_plat_sysload_t *sample)
{
    static uint64_t tick;

    memset(sample, 0, sizeof(*sample));
    sample->load1 = 2.0;
    sample->total_memory = 100;
    sample->available_memory = 25;
    sample->net_bytes = 1000 + tick * 100;
    sample->paging_events = 20 + tick;
    sample->have = BRIX_SYSLOAD_HAVE_LOAD | BRIX_SYSLOAD_HAVE_MEMORY
        | BRIX_SYSLOAD_HAVE_NET | BRIX_SYSLOAD_HAVE_PAGING;
    tick++;
    return 0;
}

static int   g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)


static void
test_loadavg(void)
{
    uint8_t pct = 77;

    CHECK(brix_cms_meter_parse_loadavg("2.00 1.50 1.00 2/345 6789\n", 4,
                                       &pct) == 0);
    CHECK(pct == 50);                       /* 2.0 load on 4 cpus = 50% */

    CHECK(brix_cms_meter_parse_loadavg("8.00 0 0", 4, &pct) == 0);
    CHECK(pct == 100);                      /* clamped at 100 */

    CHECK(brix_cms_meter_parse_loadavg("0.00 0 0", 4, &pct) == 0);
    CHECK(pct == 0);

    /* error legs: garbage / no cpus / NULL */
    pct = 77;
    CHECK(brix_cms_meter_parse_loadavg("garbage", 4, &pct) == -1);
    CHECK(brix_cms_meter_parse_loadavg("1.0 0 0", 0, &pct) == -1);
    CHECK(brix_cms_meter_parse_loadavg(NULL, 4, &pct) == -1);
    CHECK(pct == 77);                       /* out untouched on failure */
}


static void
test_meminfo(void)
{
    uint8_t pct = 77;
    const char *mi =
        "MemTotal:       16000000 kB\n"
        "MemFree:         1000000 kB\n"
        "MemAvailable:    4000000 kB\n"
        "Buffers:          500000 kB\n";

    CHECK(brix_cms_meter_parse_meminfo(mi, &pct) == 0);
    CHECK(pct == 75);                       /* (16M-4M)/16M */

    /* avail > total (procfs oddity) clamps to 0 used, not underflow */
    CHECK(brix_cms_meter_parse_meminfo(
        "MemTotal: 100 kB\nMemAvailable: 200 kB\n", &pct) == 0);
    CHECK(pct == 0);

    /* error legs: key missing / zero total / NULL */
    pct = 77;
    CHECK(brix_cms_meter_parse_meminfo("MemTotal: 100 kB\n", &pct) == -1);
    CHECK(brix_cms_meter_parse_meminfo(
        "MemTotal: 0 kB\nMemAvailable: 0 kB\n", &pct) == -1);
    CHECK(brix_cms_meter_parse_meminfo(NULL, &pct) == -1);
    CHECK(pct == 77);
}


static void
test_memory_pct(void)
{
    uint8_t pct = 77;

    CHECK(brix_cms_meter_memory_pct(1000, 250, &pct) == 0);
    CHECK(pct == 75);
    CHECK(brix_cms_meter_memory_pct(100, 200, &pct) == 0);
    CHECK(pct == 0);
    CHECK(brix_cms_meter_memory_pct(0, 0, &pct) == -1);
    CHECK(brix_cms_meter_memory_pct(100, 50, NULL) == -1);
}


static void
test_netdev(void)
{
    uint64_t total = 0;
    const char *nd =
        "Inter-|   Receive                            |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|"
        "bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 999999 10 0 0 0 0 0 0 999999 10 0 0 0 0 0 0\n"
        "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
        "  eth1: 300 3 0 0 0 0 0 0 700 7 0 0 0 0 0 0\n";

    CHECK(brix_cms_meter_parse_netdev(nd, &total) == 0);
    CHECK(total == 1000 + 2000 + 300 + 700);   /* lo excluded */

    /* error legs: headers only (no interfaces) / truncated line / NULL */
    CHECK(brix_cms_meter_parse_netdev("Inter-| Receive\n face |bytes\n",
                                      &total) == -1);
    CHECK(brix_cms_meter_parse_netdev("  eth0: 12 3\n", &total) == -1);
    CHECK(brix_cms_meter_parse_netdev(NULL, &total) == -1);
}


static void
test_vmstat(void)
{
    uint64_t v = 0;
    const char *vs =
        "nr_free_pages 123\n"
        "pgmajfault 4567\n"
        "pgfault 999999\n";

    CHECK(brix_cms_meter_parse_vmstat(vs, &v) == 0);
    CHECK(v == 4567);

    /* pgfault must not match pgmajfault's key (line-anchored search) */
    CHECK(brix_cms_meter_parse_vmstat("pgfault 111\n", &v) == -1);
    CHECK(brix_cms_meter_parse_vmstat(NULL, &v) == -1);
}


static void
test_rate_pct(void)
{
    /* 125 MB over 1s against a 125 MB/s reference = 100% */
    CHECK(brix_cms_meter_rate_pct(125000000, 1000, 125000000) == 100);
    /* half rate = 50% */
    CHECK(brix_cms_meter_rate_pct(62500000, 1000, 125000000) == 50);
    /* over-reference clamps at 100 */
    CHECK(brix_cms_meter_rate_pct(999999999, 1000, 125000000) == 100);
    /* zero elapsed / zero reference never divide */
    CHECK(brix_cms_meter_rate_pct(1000, 0, 125000000) == 0);
    CHECK(brix_cms_meter_rate_pct(1000, 1000, 0) == 0);
}


static void
test_sample_driver(void)
{
    /* The first sample reports zero deltas; the second consumes monotonic PAL
     * counters without ever accepting a configurable host path. */
    brix_cms_meter_t m;
    uint8_t out5[5] = {1, 2, 3, 4, 5};

    memset(&m, 0, sizeof(m));
    brix_cms_meter_sample(&m, 1000, out5);
    CHECK(out5[0] == 50);
    CHECK(out5[1] == 0);                    /* unprimed delta */
    CHECK(out5[2] == 0);                    /* xeq always 0 */
    CHECK(out5[3] == 75);
    CHECK(out5[4] == 0);                    /* unprimed delta */

    brix_cms_meter_sample(&m, 2000, out5);  /* primed second sample */
    CHECK(out5[1] <= 100);
    CHECK(out5[4] <= 100);
}


int
main(void)
{
    test_loadavg();
    test_meminfo();
    test_memory_pct();
    test_netdev();
    test_vmstat();
    test_rate_pct();
    test_sample_driver();

    if (g_fail) {
        printf("%d check(s) FAILED\n", g_fail);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
