/*
 * scan_throttle.h — pure rate/budget math for the storage-scan engine.
 *
 * WHAT: the leaky/token-bucket arithmetic, the budget check, and the adaptive
 *       multiplier — all pure and deterministic over an explicit `now_ns`, so
 *       they unit-test in isolation (scan_unittest.c) with synthetic clocks.
 * WHY:  the engine's primary CEPH protection is a byte-rate cap on backend
 *       reads; bounding the *math* separately from the mutex/condvar wrapper
 *       keeps the policy testable and the concurrency layer thin.
 * HOW:  a token bucket accrues `rate_bps` tokens/s up to `capacity`; a worker
 *       about to read `need` bytes asks how long to wait. Adaptive shrinks the
 *       effective rate under foreground pressure / rising backend latency.
 */
#ifndef XROOTD_SCAN_THROTTLE_H
#define XROOTD_SCAN_THROTTLE_H

#include <stdint.h>

/* Leaky token bucket over bytes. All times are CLOCK_MONOTONIC nanoseconds. */
typedef struct {
    double   rate_bps;   /* refill rate, bytes/s (0 ⇒ unlimited)                 */
    double   capacity;   /* max accrued tokens (burst), bytes                    */
    double   tokens;     /* current tokens                                       */
    uint64_t last_ns;    /* timestamp of the last refill                         */
} xrootd_scan_tb_t;

void xrootd_scan_tb_init(xrootd_scan_tb_t *tb, double rate_bps, double capacity,
                         uint64_t now_ns);

/* Accrue tokens for the elapsed interval (caps at capacity). */
void xrootd_scan_tb_refill(xrootd_scan_tb_t *tb, uint64_t now_ns);

/* Nanoseconds to wait until `need` bytes of tokens are available, given the
 * bucket state at now_ns (refills internally). 0 ⇒ available now. rate 0 ⇒ 0. */
uint64_t xrootd_scan_tb_wait_ns(xrootd_scan_tb_t *tb, double need, uint64_t now_ns);

/* Spend `need` tokens (may drive tokens negative only down to -capacity). */
void xrootd_scan_tb_consume(xrootd_scan_tb_t *tb, double need);

/* Budget: stop when either ceiling is crossed (0 ⇒ that ceiling is disabled). */
typedef struct {
    uint64_t max_bytes;
    double   max_seconds;
} xrootd_scan_budget_t;

/* Non-zero ⇒ budget exhausted (bytes_done ≥ max_bytes, or elapsed ≥ max_seconds). */
int xrootd_scan_budget_hit(const xrootd_scan_budget_t *b,
                           uint64_t bytes_done, double elapsed_s);

/* Adaptive multiplier in [0.1, 1.0] applied to the rate. Rising foreground
 * pressure (active non-scan requests) or rising backend latency vs. the nominal
 * baseline shrinks it. Pure: same inputs ⇒ same output. */
double xrootd_scan_adapt(int foreground_active, double latency_ewma_ms,
                         double nominal_latency_ms);

#endif /* XROOTD_SCAN_THROTTLE_H */
