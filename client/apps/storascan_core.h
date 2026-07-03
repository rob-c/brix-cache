/*
 * storascan_core.h — pure, side-effect-free core for xrdstorascan.
 *
 * WHAT: the protocol-free arithmetic + decision logic behind the client-side
 *       `bench` (B1) and `verify --wire` (A1) modes — latency percentiles,
 *       throughput/IOPS, and the checksum-comparison verdict.
 * WHY:  isolating the math from the network I/O makes both modes unit-testable
 *       standalone (no server, no libbrix), mirroring the repo's
 *       *_unittest.c pattern.
 * HOW:  pure functions over caller-owned buffers; no allocation that outlives a
 *       call, no globals.
 */
#ifndef STORASCAN_CORE_H
#define STORASCAN_CORE_H

#include <stddef.h>
#include <stdint.h>

/* ---- verify (A1) — checksum comparison verdict ---------------------------- */

typedef enum {
    STORASCAN_CKS_MATCH = 0,   /* both present, equal (case-insensitive)        */
    STORASCAN_CKS_MISMATCH,    /* both present, differ                          */
    STORASCAN_CKS_MISSING      /* nothing to compare against (stored NULL/empty)*/
} storascan_cks_status;

/* Compare a freshly computed hex digest against the stored/server digest.
 * Comparison is case-insensitive and ignores surrounding ASCII whitespace.
 * stored == NULL or empty (after trim) ⇒ STORASCAN_CKS_MISSING. */
storascan_cks_status storascan_cks_compare(const char *computed_hex,
                                           const char *stored_hex);

/* ---- bench (B1) — latency / throughput statistics ------------------------- */

typedef struct {
    double   p50_ms;
    double   p95_ms;
    double   p99_ms;
    double   throughput_mibps;   /* MiB/s over the whole run                   */
    double   iops;               /* completed I/O ops per second               */
    uint64_t ops;
    uint64_t bytes;
    double   elapsed_s;
} storascan_bench_result;

/* Nearest-rank percentile (pct in [0,100]) over an ascending-SORTED array of
 * latency samples in milliseconds. n == 0 ⇒ 0.0. Does not modify the input. */
double storascan_percentile_ms(const double *sorted_ms, size_t n, double pct);

/* Compute a full bench result from raw (unsorted) per-op latency samples plus
 * the run totals. Sorts a private copy — the caller's lat_ms is left untouched.
 * elapsed_s <= 0 ⇒ throughput/iops reported as 0. */
void storascan_bench_compute(const double *lat_ms, size_t n,
                             uint64_t bytes, double elapsed_s,
                             storascan_bench_result *out);

#endif /* STORASCAN_CORE_H */
