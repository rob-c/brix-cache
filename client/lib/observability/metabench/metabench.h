/*
 * metabench.h — deterministic metadata-storm workload generator + latency
 * percentiles, shared by tests/tools/pblock_meta_bench.c and
 * client/apps/diag_metabench.c. Private client header (not a public API).
 *
 * WHAT: one worker owns subtree /w<id>/d<d>/f<f>; the program is fixed so the
 *       expected post-create namespace is known exactly — catalog integrity is a
 *       strict equality check, not a smoke test.
 * WHY:  prove pblock metadata correctness + performance under concurrency.
 * HOW:  this header/TU is PURE (planning + percentile + result printers, no wire
 *       I/O) so it compiles + unit-tests standalone with only libc. The threaded
 *       GSI runner that needs libbrix lives in metabench_run.{c,h}.
 */
#ifndef XRDC_METABENCH_H
#define XRDC_METABENCH_H

#include <stddef.h>
#include <stdio.h>

typedef enum { MB_CREATE = 0, MB_REMOVE = 1 } metabench_phase;

typedef struct {
    int workers;          /* concurrent GSI sessions (one thread + one conn each) */
    int dirs_per_worker;  /* D: subdirs per worker subtree */
    int files_per_dir;    /* F: files per subdir */
    int p99_ceil_ms;      /* fail if storm p99 exceeds this; 0 = no ceiling */
} metabench_plan;

/* WHAT: derive a balanced D/F from a per-worker op budget.
 * HOW:  CREATE ops/worker = 2 + 2*D + 3*D*F; fix F=4, solve D, clamp >=1. */
void metabench_plan_init(metabench_plan *p, int workers, int ops_per_worker,
                         int p99_ceil_ms);

/* Total counted CREATE-phase ops across all workers (drives ops/sec). */
long metabench_storm_ops(const metabench_plan *p);

typedef struct {
    char     path[512];
    unsigned mode;     /* final mode after chmod */
    int      is_dir;
} metabench_entry;

/* Fill `out` (sorted ascending by path) with the namespace a full CREATE run
 * produces. Returns the total count (may exceed cap; only cap are written). */
size_t metabench_expected(const metabench_plan *p, metabench_entry *out,
                          size_t cap);

/* Linear-interpolated percentile (pct in [0,100]) over `ms`. Non-destructive:
 * copies + sorts internally. Returns 0 for n==0. */
double metabench_percentile(const double *ms, size_t n, double pct);

/* ---- result of a run (filled by metabench_run in metabench_run.c) -------- */

typedef struct { int id; long ops, failures; double ops_per_sec; } metabench_wstat;

typedef struct {
    metabench_phase phase;
    long   total_ops, failures;
    double wall_s, ops_per_sec, p50_ms, p95_ms, p99_ms;
    int    nworkers;
    metabench_wstat per_worker[64];
} metabench_result;

void metabench_result_print(const metabench_result *r, FILE *f);  /* human */
void metabench_result_json(const metabench_result *r, FILE *f);   /* one JSON line */

#endif /* XRDC_METABENCH_H */
