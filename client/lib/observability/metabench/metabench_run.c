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

    for (int i = 0; i < W; i++) {
        wk[i].url = url;
        wk[i].opts = opts;
        wk[i].plan = plan;
        wk[i].phase = phase;
        wk[i].id = i;
        wk[i].lat_cap = per_cap;
        wk[i].lat_ms = calloc((size_t) per_cap, sizeof(double));
    }

    uint64_t t0 = brix_mono_ns();
    for (int i = 0; i < W; i++) {
        pthread_create(&th[i], NULL, mb_thread, &wk[i]);
    }
    for (int i = 0; i < W; i++) {
        pthread_join(th[i], NULL);
    }
    double wall = (double) (brix_mono_ns() - t0) / 1e9;

    memset(out, 0, sizeof(*out));
    out->phase = phase;
    out->nworkers = W;
    out->wall_s = wall;

    long total_lat = 0;
    for (int i = 0; i < W; i++) {
        total_lat += wk[i].lat_n;
    }
    double *all = calloc((size_t) (total_lat ? total_lat : 1), sizeof(double));
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

    out->ops_per_sec = wall > 0 ? (double) out->total_ops / wall : 0;
    out->p50_ms = metabench_percentile(all, (size_t) k, 50.0);
    out->p95_ms = metabench_percentile(all, (size_t) k, 95.0);
    out->p99_ms = metabench_percentile(all, (size_t) k, 99.0);

    free(all);
    free(wk);
    free(th);

    int ok = (out->failures == 0)
          && (plan->p99_ceil_ms == 0 || out->p99_ms <= plan->p99_ceil_ms);
    return ok ? 0 : -1;
}
