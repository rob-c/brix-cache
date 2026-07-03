/*
 * scan_throttle.c — pure rate/budget math (see scan_throttle.h).
 *
 * Deterministic over an explicit now_ns so it unit-tests with a synthetic clock
 * (scan_unittest.c). The mutex/condvar wrapper that drives this lives in the
 * engine; this file is just the arithmetic.
 */
#include "scan_throttle.h"

void
brix_scan_tb_init(brix_scan_tb_t *tb, double rate_bps, double capacity,
                    uint64_t now_ns)
{
    tb->rate_bps = rate_bps;
    tb->capacity = capacity;
    tb->tokens = capacity;    /* start full: a burst up to capacity is allowed   */
    tb->last_ns = now_ns;
}

void
brix_scan_tb_refill(brix_scan_tb_t *tb, uint64_t now_ns)
{
    double dt_s;

    if (tb->rate_bps <= 0.0) {
        return;
    }
    if (now_ns <= tb->last_ns) {       /* clock went backwards / no time passed   */
        tb->last_ns = now_ns;
        return;
    }
    dt_s = (double) (now_ns - tb->last_ns) / 1.0e9;
    tb->tokens += tb->rate_bps * dt_s;
    if (tb->tokens > tb->capacity) {
        tb->tokens = tb->capacity;
    }
    tb->last_ns = now_ns;
}

uint64_t
brix_scan_tb_wait_ns(brix_scan_tb_t *tb, double need, uint64_t now_ns)
{
    double deficit;

    if (tb->rate_bps <= 0.0) {
        return 0;                       /* unlimited                               */
    }
    brix_scan_tb_refill(tb, now_ns);
    if (tb->tokens >= need) {
        return 0;
    }
    deficit = need - tb->tokens;
    return (uint64_t) ((deficit / tb->rate_bps) * 1.0e9);
}

void
brix_scan_tb_consume(brix_scan_tb_t *tb, double need)
{
    tb->tokens -= need;
    if (tb->tokens < -tb->capacity) {
        tb->tokens = -tb->capacity;
    }
}

int
brix_scan_budget_hit(const brix_scan_budget_t *b, uint64_t bytes_done,
                       double elapsed_s)
{
    if (b->max_bytes > 0 && bytes_done >= b->max_bytes) {
        return 1;
    }
    if (b->max_seconds > 0.0 && elapsed_s >= b->max_seconds) {
        return 1;
    }
    return 0;
}

double
brix_scan_adapt(int foreground_active, double latency_ewma_ms,
                  double nominal_latency_ms)
{
    double pressure_factor;
    double latency_factor;
    double m;

    if (nominal_latency_ms <= 0.0) {
        nominal_latency_ms = 1.0;
    }
    if (foreground_active < 0) {
        foreground_active = 0;
    }

    /* each active foreground request damps the rate; latency above nominal
     * shrinks it proportionally */
    pressure_factor = 1.0 / (1.0 + 0.5 * (double) foreground_active);
    latency_factor = (latency_ewma_ms <= nominal_latency_ms)
                     ? 1.0
                     : nominal_latency_ms / latency_ewma_ms;

    m = pressure_factor * latency_factor;
    if (m > 1.0) {
        m = 1.0;
    }
    if (m < 0.1) {
        m = 0.1;
    }
    return m;
}
