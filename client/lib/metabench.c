/*
 * metabench.c — PURE metadata workload planning + percentiles + result printers.
 * No wire I/O, no libbrix dependency: builds + unit-tests standalone with libc.
 * The threaded GSI runner lives in metabench_run.c.
 */
#include "metabench.h"
#include <stdlib.h>
#include <string.h>

/* WHAT: choose D (dirs) and F (files/dir) so per-worker CREATE op count is close
 * to `ops_per_worker`. WHY: hit ~1000 total with a small balanced tree.
 * HOW: CREATE ops/worker = 2 + 2*D + 3*D*F; fix F=4, solve D, clamp >=1. */
void metabench_plan_init(metabench_plan *p, int workers, int ops_per_worker,
                         int p99_ceil_ms)
{
    int F = 4;
    int D = (ops_per_worker - 2) / (2 + 3 * F);   /* 2 + 2D + 3DF = budget */
    if (D < 1) {
        D = 1;
    }
    p->workers = workers < 1 ? 1 : workers;
    p->files_per_dir = F;
    p->dirs_per_worker = D;
    p->p99_ceil_ms = p99_ceil_ms;
}

/* counted CREATE ops, all workers. */
long metabench_storm_ops(const metabench_plan *p)
{
    long per = 2L + 2L * p->dirs_per_worker
             + 3L * p->dirs_per_worker * p->files_per_dir;
    return per * p->workers;
}

/* WHAT: emit the exact namespace a CREATE run leaves, sorted by path.
 * HOW: /w<id> (0755), /w<id>/d<d> (0700), /w<id>/d<d>/f<f> (0640). Built in
 * natural order then qsort'd, so callers can diff against a sorted listing. */
static int entry_cmp(const void *a, const void *b)
{
    return strcmp(((const metabench_entry *) a)->path,
                  ((const metabench_entry *) b)->path);
}

size_t metabench_expected(const metabench_plan *p, metabench_entry *out,
                          size_t cap)
{
    size_t n = 0;

    for (int w = 0; w < p->workers; w++) {
        if (n < cap) {
            snprintf(out[n].path, sizeof(out[n].path), "/w%d", w);
            out[n].mode = 0755;
            out[n].is_dir = 1;
        }
        n++;
        for (int d = 0; d < p->dirs_per_worker; d++) {
            if (n < cap) {
                snprintf(out[n].path, sizeof(out[n].path), "/w%d/d%d", w, d);
                out[n].mode = 0700;
                out[n].is_dir = 1;
            }
            n++;
            for (int f = 0; f < p->files_per_dir; f++) {
                if (n < cap) {
                    snprintf(out[n].path, sizeof(out[n].path),
                             "/w%d/d%d/f%d", w, d, f);
                    out[n].mode = 0640;
                    out[n].is_dir = 0;
                }
                n++;
            }
        }
    }

    size_t sortable = n < cap ? n : cap;
    qsort(out, sortable, sizeof(*out), entry_cmp);
    return n;
}

/* linear-interpolated percentile over a copy of ms. */
static int dbl_cmp(const void *a, const void *b)
{
    double x = *(const double *) a, y = *(const double *) b;
    return (x > y) - (x < y);
}

double metabench_percentile(const double *ms, size_t n, double pct)
{
    if (n == 0) {
        return 0.0;
    }

    double *c = malloc(n * sizeof(*c));
    if (c == NULL) {
        return 0.0;
    }
    memcpy(c, ms, n * sizeof(*c));
    qsort(c, n, sizeof(*c), dbl_cmp);

    double rank = (pct / 100.0) * (double) (n - 1);
    size_t lo = (size_t) rank;
    double frac = rank - (double) lo;
    double v = (lo + 1 < n) ? c[lo] + frac * (c[lo + 1] - c[lo]) : c[lo];

    free(c);
    return v;
}

/* ---- result printers (pure: just formatting) ----------------------------- */

void metabench_result_print(const metabench_result *r, FILE *f)
{
    fprintf(f, "  %ld ops, %ld fail, %.0f ops/s\n",
            r->total_ops, r->failures, r->ops_per_sec);
    fprintf(f, "  p50=%.1fms p95=%.1fms p99=%.1fms  %s\n",
            r->p50_ms, r->p95_ms, r->p99_ms,
            r->failures == 0 ? "PASS" : "FAIL");
}

void metabench_result_json(const metabench_result *r, FILE *f)
{
    fprintf(f, "{\"phase\":%d,\"total_ops\":%ld,\"failures\":%ld,"
               "\"ops_per_sec\":%.1f,\"p50_ms\":%.3f,\"p95_ms\":%.3f,"
               "\"p99_ms\":%.3f,\"wall_s\":%.3f,\"workers\":%d}\n",
            (int) r->phase, r->total_ops, r->failures, r->ops_per_sec,
            r->p50_ms, r->p95_ms, r->p99_ms, r->wall_s, r->nworkers);
}
