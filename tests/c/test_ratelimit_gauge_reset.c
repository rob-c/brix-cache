/*
 * test_ratelimit_gauge_reset.c — regression: leaked concurrency/open gauges in
 * the rate-limit SHM zone must be cleared on reload ("throttle wedges after
 * many reboots").
 *
 * THE BUG
 *   Each rate-limit node carries in-use GAUGES: in_flight (concurrency) and
 *   open_files (per-user open handles). They are incremented on acquire and
 *   decremented only on the matched release. A worker SIGKILLed mid-request
 *   (e.g. at reload's worker_shutdown_timeout) never runs release, so the
 *   increment leaks. The node lives in the SHM zone, which is ADOPTED across
 *   reload (ratelimit_zone.c: "live buckets survive the reload"), so the leaked
 *   gauge persists — and accumulates every restart cycle. Eviction only frees
 *   the LRU tail under slab pressure, so a hot key (or a small-keyspace zone)
 *   is never cleared. Eventually the gauge reaches the cap and that key — or,
 *   for a global throttle, the whole server — is rejected FOREVER.
 *
 * THE FIX
 *   xrootd_rl_zone_reset_gauges() zeroes in_flight + open_files on every node,
 *   called on reload adoption. This bounds any crash-leak to one generation.
 *   The time-windowed rate/bandwidth buckets (req_total, bytes_total,
 *   req_excess, ...) are preserved so a reload is not a rate-limit bypass.
 *
 * TESTS
 *   1. reset zeroes in_flight + open_files on every node
 *   2. reset PRESERVES the rate/bandwidth buckets (req_total, bytes_total)
 *   3. empty zone is handled without crashing
 */
#include "net/ratelimit/ratelimit.h"

#include <stdio.h>
#include <string.h>

static int failures;
static void check(int cond, const char *name)
{
    printf("  %-52s %s\n", name, cond ? "PASS" : "FAIL");
    if (!cond) failures++;
}

/* Node with room for a short key (the flexible key_str[] member). */
typedef struct { xrootd_rl_node_t n; char pad[16]; } node_box_t;

static void
seed(node_box_t *b, ngx_uint_t inflight, ngx_uint_t openf, uint64_t reqtot)
{
    memset(b, 0, sizeof(*b));
    b->n.in_flight   = inflight;
    b->n.open_files  = openf;
    b->n.req_total   = reqtot;
    b->n.bytes_total = reqtot * 10;
    b->n.req_excess  = 1234;
}

int
main(void)
{
    xrootd_rl_shctx_t sh;
    node_box_t a, b, c;

    memset(&sh, 0, sizeof(sh));
    ngx_queue_init(&sh.queue);

    seed(&a, 5, 3, 100);
    seed(&b, 1, 0, 7);
    seed(&c, 0, 9, 42);
    ngx_queue_insert_head(&sh.queue, &a.n.queue);
    ngx_queue_insert_head(&sh.queue, &b.n.queue);
    ngx_queue_insert_head(&sh.queue, &c.n.queue);

    xrootd_rl_zone_reset_gauges(&sh);

    check(a.n.in_flight == 0 && b.n.in_flight == 0 && c.n.in_flight == 0,
          "in_flight zeroed on every node");
    check(a.n.open_files == 0 && b.n.open_files == 0 && c.n.open_files == 0,
          "open_files zeroed on every node");
    check(a.n.req_total == 100 && b.n.req_total == 7 && c.n.req_total == 42,
          "req_total (rate bucket) preserved");
    check(a.n.bytes_total == 1000 && a.n.req_excess == 1234,
          "bytes_total + req_excess (rate/bw state) preserved");

    /* empty zone: must not crash */
    xrootd_rl_shctx_t empty;
    memset(&empty, 0, sizeof(empty));
    ngx_queue_init(&empty.queue);
    xrootd_rl_zone_reset_gauges(&empty);
    check(1, "empty zone handled without crashing");

    if (failures) { printf("\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nall rate-limit gauge-reset checks passed\n");
    return 0;
}
