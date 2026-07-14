/*
 * metabench_run.c — threaded GSI runner for the metadata storm.
 *
 * WHAT: plan->workers threads, each holding ONE persistent GSI connection, run a
 *       deterministic mkdir/chmod/truncate/stat (CREATE) or rm/rmdir (REMOVE)
 *       program over its own /w<id> subtree, timing every op.
 * WHY:  isolate the pblock backend under concurrency — the cost measured is the
 *       backend's, not repeated handshakes or process startup.
 * HOW:  one brix_conn per thread (brix_conn is one-request-in-flight and not
 *       thread-safe; one-per-thread is the documented MT pattern). Latencies are
 *       merged and reduced to p50/p95/p99 by the pure metabench helpers.
 */
#include "metabench_run.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* one worker's slice: connect (GSI) once, run its subtree, record latencies. */
typedef struct {
    const brix_url  *url;
    const brix_opts *opts;
    const metabench_plan *plan;
    metabench_phase  phase;
    int     id;
    double *lat_ms;     /* capacity lat_cap, filled lat_n */
    long    lat_cap;
    long    lat_n;
    long    ops, failures;
} mb_worker;

/* record one op's latency (drop silently once the per-worker buffer is full). */
static void mb_record(mb_worker *w, uint64_t t0)
{
    double ms = (double) (brix_mono_ns() - t0) / 1e6;
    if (w->lat_n < w->lat_cap) {
        w->lat_ms[w->lat_n++] = ms;
    }
}

/* CREATE: mkdir+chmod the tree, then create+chmod+stat each file. The stat
 * asserts the chmod persisted (mode read-back), so a silent mode loss fails. */
static void mb_create(mb_worker *w, brix_conn *c)
{
    const metabench_plan *p = w->plan;
    char path[512];
    brix_status st;
    uint64_t t0;

    snprintf(path, sizeof(path), "/w%d", w->id);
    t0 = brix_mono_ns();
    if (brix_mkdir(c, path, 0755, 0, &st) != 0) { w->failures++; }
    w->ops++; mb_record(w, t0);

    t0 = brix_mono_ns();
    if (brix_chmod(c, path, 0755, &st) != 0) { w->failures++; }
    w->ops++; mb_record(w, t0);

    for (int d = 0; d < p->dirs_per_worker; d++) {
        snprintf(path, sizeof(path), "/w%d/d%d", w->id, d);
        t0 = brix_mono_ns();
        if (brix_mkdir(c, path, 0700, 0, &st) != 0) { w->failures++; }
        w->ops++; mb_record(w, t0);

        t0 = brix_mono_ns();
        if (brix_chmod(c, path, 0700, &st) != 0) { w->failures++; }
        w->ops++; mb_record(w, t0);

        for (int f = 0; f < p->files_per_dir; f++) {
            snprintf(path, sizeof(path), "/w%d/d%d/f%d", w->id, d, f);

            /* create an empty file: open kXR_new (force=0) then close — the same
             * metadata-only path `xrdfs touch` uses (truncate(2) needs an
             * existing target, so it is NOT a create). */
            brix_file fh;
            t0 = brix_mono_ns();
            if (brix_file_open_write(c, path, 0 /* new */, 0 /* posc */, &fh, &st) != 0) {
                w->failures++;
            } else if (brix_file_close(c, &fh, &st) != 0) {
                w->failures++;
            }
            w->ops++; mb_record(w, t0);

            t0 = brix_mono_ns();
            if (brix_chmod(c, path, 0640, &st) != 0) { w->failures++; }
            w->ops++; mb_record(w, t0);

            brix_statinfo si;
            t0 = brix_mono_ns();
            if (brix_stat(c, path, &si, &st) != 0) {
                w->failures++;
            } else if (si.have_ext && (si.mode & 0777) != 0640) {
                w->failures++;   /* chmod did not persist */
            }
            w->ops++; mb_record(w, t0);
        }
    }
}

/* REMOVE: rm files, rmdir dirs bottom-up; leaves the store as it started. */
static void mb_remove(mb_worker *w, brix_conn *c)
{
    const metabench_plan *p = w->plan;
    char path[512];
    brix_status st;
    uint64_t t0;

    for (int d = 0; d < p->dirs_per_worker; d++) {
        for (int f = 0; f < p->files_per_dir; f++) {
            snprintf(path, sizeof(path), "/w%d/d%d/f%d", w->id, d, f);
            t0 = brix_mono_ns();
            if (brix_rm(c, path, &st) != 0) { w->failures++; }
            w->ops++; mb_record(w, t0);
        }
        snprintf(path, sizeof(path), "/w%d/d%d", w->id, d);
        t0 = brix_mono_ns();
        if (brix_rmdir(c, path, &st) != 0) { w->failures++; }
        w->ops++; mb_record(w, t0);
    }

    snprintf(path, sizeof(path), "/w%d", w->id);
    t0 = brix_mono_ns();
    if (brix_rmdir(c, path, &st) != 0) { w->failures++; }
    w->ops++; mb_record(w, t0);
}

/* thread entry: one GSI session, then the phase program. A connect failure marks
 * every planned op for this worker as failed (so the run cannot pass). */
static void *mb_thread(void *arg)
{
    mb_worker *w = arg;
    brix_conn  c;
    brix_status st;

    brix_status_clear(&st);
    if (brix_connect(&c, w->url, w->opts, &st) != 0) {
        w->failures = w->lat_cap;
        w->ops = w->lat_cap;
        return NULL;
    }

    if (w->phase == MB_CREATE) {
        mb_create(w, &c);
    } else {
        mb_remove(w, &c);
    }

    brix_close(&c);
    return NULL;
}

/* ---- Populate the per-worker slice array from the shared plan ----
 *
 * WHAT: fills wk[0..W-1] with the immutable run inputs (url/opts/plan/phase,
 *       sequential id, latency-buffer capacity) and allocates each worker's
 *       zeroed latency buffer. No return value; a failed lat_ms calloc leaves a
 *       NULL buffer that mb_record tolerates (it only writes when lat_n<lat_cap).
 *
 * WHY:  every worker needs the same read-only context plus its own private
 *       latency storage; hoisting this out of metabench_run keeps the
 *       orchestrator flat and below the complexity cap.
 *
 * HOW:  1. iterate i over [0,W); 2. copy the shared pointers and scalar id/cap;
 *       3. calloc a per_cap-entry double buffer for that worker.
 */
static void mb_init_workers(mb_worker *wk, int W, const brix_url *url,
                            const brix_opts *opts, const metabench_plan *plan,
                            metabench_phase phase, long per_cap)
{
    for (int i = 0; i < W; i++) {
        wk[i].url = url;
        wk[i].opts = opts;
        wk[i].plan = plan;
        wk[i].phase = phase;
        wk[i].id = i;
        wk[i].lat_cap = per_cap;
        wk[i].lat_ms = calloc((size_t) per_cap, sizeof(double));
    }
}

/* ---- Launch, join, and time the worker threads ----
 *
 * WHAT: spawns W threads on mb_thread (one persistent GSI connection each),
 *       joins them all, and returns the wall-clock duration in seconds.
 *
 * WHY:  the storm's throughput and per-op rates are derived from this single
 *       wall interval; measuring it around exactly the create/join bracket keeps
 *       the timing honest and confines the pthread plumbing to one helper.
 *
 * HOW:  1. sample a monotonic start; 2. pthread_create each worker slice;
 *       3. pthread_join each in order; 4. return elapsed nanoseconds / 1e9.
 */
static double mb_run_workers(mb_worker *wk, pthread_t *th, int W)
{
    uint64_t t0 = brix_mono_ns();
    for (int i = 0; i < W; i++) {
        pthread_create(&th[i], NULL, mb_thread, &wk[i]);
    }
    for (int i = 0; i < W; i++) {
        pthread_join(th[i], NULL);
    }
    return (double) (brix_mono_ns() - t0) / 1e9;
}

/* ---- Sum the recorded latency counts across all workers ----
 *
 * WHAT: returns the total number of latency samples recorded by wk[0..W-1]
 *       (each worker's lat_n), used to size the merged latency array.
 *
 * WHY:  the merged buffer must be exactly large enough for every sample; a
 *       separate counting pass lets the caller allocate once before merging.
 *
 * HOW:  1. accumulate wk[i].lat_n over i in [0,W); 2. return the sum.
 */
static long mb_total_lat(const mb_worker *wk, int W)
{
    long total_lat = 0;
    for (int i = 0; i < W; i++) {
        total_lat += wk[i].lat_n;
    }
    return total_lat;
}

/* ---- Merge worker results into the output and the combined latency array ----
 *
 * WHAT: folds each worker's ops/failures and per-worker record into out, copies
 *       every recorded latency into all[], frees each worker's lat_ms, and
 *       returns the number of samples written to all[]. When all is NULL
 *       (merged-buffer alloc failed) the inner copy is skipped and 0 is returned.
 *
 * WHY:  aggregation is the bulk of the run's branching; isolating it keeps the
 *       orchestrator flat while preserving the exact fold order and the
 *       per-worker latency-buffer ownership (freed here, where it is consumed).
 *
 * HOW:  1. iterate i over [0,W); 2. add ops/failures into totals and fill the
 *       per_worker[i] row (ops_per_sec guarded on wall>0); 3. append each of
 *       wk[i].lat_n samples into all[k++] only while all is non-NULL; 4. free
 *       wk[i].lat_ms; 5. return k, the merged sample count.
 */
static long mb_aggregate(metabench_result *out, mb_worker *wk, int W,
                         double *all, double wall)
{
    long k = 0;
    for (int i = 0; i < W; i++) {
        out->total_ops += wk[i].ops;
        out->failures += wk[i].failures;
        out->per_worker[i].id = i;
        out->per_worker[i].ops = wk[i].ops;
        out->per_worker[i].failures = wk[i].failures;
        out->per_worker[i].ops_per_sec = wall > 0 ? (double) wk[i].ops / wall : 0;
        for (long j = 0; j < wk[i].lat_n && all != NULL; j++) {
            all[k++] = wk[i].lat_ms[j];
        }
        free(wk[i].lat_ms);
    }
    return k;
}

/* ---- Decide pass/fail for the completed storm ----
 *
 * WHAT: returns 0 when the run passed (zero failures AND, if a p99 ceiling is
 *       set, the measured p99 is within it) and -1 otherwise.
 *
 * WHY:  the verdict couples several conditions; naming it keeps the exit
 *       criterion in one place and out of the orchestrator's branch budget. A
 *       p99_ceil_ms of 0 means "no latency ceiling", so only failures gate.
 *
 * HOW:  1. require out->failures == 0; 2. AND (p99_ceil_ms == 0 OR p99 within
 *       ceiling); 3. map the boolean to 0 (pass) / -1 (fail).
 */
static int mb_verdict(const metabench_result *out, const metabench_plan *plan)
{
    int ok = (out->failures == 0)
          && (plan->p99_ceil_ms == 0 || out->p99_ms <= plan->p99_ceil_ms);
    return ok ? 0 : -1;
}

int metabench_run(const brix_url *url, const brix_opts *opts,
                  const metabench_plan *plan, metabench_phase phase,
                  metabench_result *out, brix_status *st)
{
    (void) st;

    int W = plan->workers;
    if (W > 64) {
        W = 64;
    }
    long per_cap = metabench_storm_ops(plan) / plan->workers + 8;

    mb_worker *wk = calloc((size_t) W, sizeof(*wk));
    pthread_t *th = calloc((size_t) W, sizeof(*th));
    if (wk == NULL || th == NULL) {
        free(wk);
        free(th);
        return -1;
    }

    mb_init_workers(wk, W, url, opts, plan, phase, per_cap);

    double wall = mb_run_workers(wk, th, W);

    memset(out, 0, sizeof(*out));
    out->phase = phase;
    out->nworkers = W;
    out->wall_s = wall;

    long total_lat = mb_total_lat(wk, W);
    double *all = calloc((size_t) (total_lat ? total_lat : 1), sizeof(double));
    long k = mb_aggregate(out, wk, W, all, wall);

    out->ops_per_sec = wall > 0 ? (double) out->total_ops / wall : 0;
    out->p50_ms = metabench_percentile(all, (size_t) k, 50.0);
    out->p95_ms = metabench_percentile(all, (size_t) k, 95.0);
    out->p99_ms = metabench_percentile(all, (size_t) k, 99.0);

    free(all);
    free(wk);
    free(th);

    return mb_verdict(out, plan);
}
