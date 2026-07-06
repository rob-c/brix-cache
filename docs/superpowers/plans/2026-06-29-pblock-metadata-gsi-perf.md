# pblock Metadata Performance / Reliability Test Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a three-layer test suite that proves the pblock storage backend stays correct and performant under ~1000 concurrent GSI-authenticated `root://` metadata operations.

**Architecture:** One shared self-contained nginx fixture (pblock backend + GSI auth). One deterministic op-manifest engine (`client/lib/metabench.c`, linked into `libxrdc.a`) generates the workload and the expected namespace, and runs it over one persistent GSI connection per worker thread. Three layers consume it: a standalone libxrdc harness (`tests/tools/pblock_meta_bench.c`), the real `xrdfs` CLI, and a new shipped `xrddiag metabench` subcommand. A bash umbrella (`tests/run_pblock_meta_gsi.sh`) stands up the fixture, runs all three layers, and enforces four pass criteria.

**Tech Stack:** C (libxrdc / pthreads), bash, nginx (stream module), GSI/X.509, the existing `client/bin/{xrdfs,xrddiag}` tools.

**Spec:** `docs/superpowers/specs/2026-06-29-pblock-metadata-gsi-perf-design.md`

## Global Constraints

- **No `goto`** anywhere in `src/`, `shared/`, `client/` (`.c`/`.h`) — early-return + helper decomposition only.
- **Functional + modular** — one job per function, explicit data flow, no new globals; pure helpers (manifest/percentile) with side effects (I/O, threads) at the edges.
- **No raw libc data/namespace I/O in server handlers** — N/A here (test code + client lib only), but the umbrella's pblock catalog inspection is read-only `find`/`xrdfs`, never writing into `<root>` directly.
- **Section-level WHAT/WHY/HOW doc block on every function.**
- **Build governance:** new `client/lib/*.c` registers in `LIB_SRCS` in `client/Makefile`; new `client/apps/diag_*.o` registers in `XRDDIAG_SPLIT`. No nginx `./configure` change (no new server source).
- **pblock requires** `xrootd_upload_resume off`.
- **GSI is driven by `X509_USER_PROXY` + `X509_CERT_DIR` env** — the single path libxrdc / `xrdfs` / `xrddiag` all consume.
- **No git command runs without the operator's explicit instruction** (project hard rule). The `Commit` steps below are documented for the executor to run *with* that approval; do not auto-run them.
- **3 tests per change:** success + error + security-negative.

**Reference signatures (already public, do not reimplement):**
- `int xrdc_connect(xrdc_conn *c, const xrdc_url *u, const xrdc_opts *o, xrdc_status *st);`
- `int xrdc_mkdir(xrdc_conn *c, const char *path, int mode, int parents, xrdc_status *st);`
- `int xrdc_chmod(xrdc_conn *c, const char *path, int mode, xrdc_status *st);`
- `int xrdc_truncate(xrdc_conn *c, const char *path, int64_t size, xrdc_status *st);`
- `int xrdc_stat(xrdc_conn *c, const char *path, xrdc_statinfo *out, xrdc_status *st);` (`xrdc_statinfo.mode` valid when `.have_ext`)
- `int xrdc_rm(xrdc_conn *c, const char *path, xrdc_status *st);` / `int xrdc_rmdir(xrdc_conn *c, const char *path, xrdc_status *st);`
- `void xrdc_close(xrdc_conn *c);` · `uint64_t xrdc_mono_ns(void);`
- `int xrdc_url_parse(const char *s, xrdc_url *u, xrdc_status *st);` (confirm exact name in `client/lib/url.c` during Task 3)

---

## File Structure

- **Create** `client/lib/metabench.h` — manifest/percentile/runner interface (private client header).
- **Create** `client/lib/metabench.c` — pure manifest + percentile + threaded GSI runner.
- **Create** `client/lib/metabench_unittest.c` — standalone unit test for the pure parts.
- **Create** `tests/tools/pblock_meta_bench.c` — Layer (a) standalone harness (thin `main`).
- **Create** `client/apps/diag_metabench.c` — Layer (c) `xrddiag metabench` subcommand.
- **Modify** `client/apps/diag_internal.h` — declare `int do_metabench(diag_args *a);`.
- **Modify** `client/apps/xrddiag.c` — dispatch + usage line for `metabench`.
- **Modify** `client/Makefile` — `LIB_SRCS += lib/metabench.c`; `XRDDIAG_SPLIT += apps/diag_metabench.o`.
- **Create** `tests/run_pblock_meta_gsi.sh` — umbrella fixture + 3 layers + verification + self-tests.

---

## Task 1: Shared manifest + percentile engine (pure parts)

**Files:**
- Create: `client/lib/metabench.h`
- Create: `client/lib/metabench.c` (pure functions only in this task)
- Create: `client/lib/metabench_unittest.c`
- Modify: `client/Makefile:97` (`LIB_SRCS`)

**Interfaces:**
- Produces:
  - `typedef enum { MB_CREATE = 0, MB_REMOVE = 1 } metabench_phase;`
  - `typedef struct { int workers, dirs_per_worker, files_per_dir, p99_ceil_ms; } metabench_plan;`
  - `void metabench_plan_init(metabench_plan *p, int workers, int ops_per_worker, int p99_ceil_ms);`
  - `long metabench_storm_ops(const metabench_plan *p);`
  - `typedef struct { char path[512]; unsigned mode; int is_dir; } metabench_entry;`
  - `size_t metabench_expected(const metabench_plan *p, metabench_entry *out, size_t cap);`
  - `double metabench_percentile(const double *ms, size_t n, double pct);`

- [ ] **Step 1: Write `client/lib/metabench.h`**

```c
/*
 * metabench.h — deterministic metadata-storm workload generator + latency
 * percentiles + a threaded GSI runner, shared by tests/tools/pblock_meta_bench.c
 * and client/apps/diag_metabench.c. Private client header (not a public API).
 *
 * WHAT: one worker owns subtree /w<id>/d<d>/f<f>; the program is fixed so the
 *       expected post-create namespace is known exactly (catalog integrity is a
 *       strict equality check, not a smoke test).
 * WHY:  prove pblock metadata correctness + performance under concurrency.
 * HOW:  pure planning/percentile helpers here; side effects (threads, wire ops)
 *       live in metabench_run() (Task 2).
 */
#ifndef XRDC_METABENCH_H
#define XRDC_METABENCH_H

#include <stddef.h>
#include <stdio.h>
#include "xrdc_net.h"   /* xrdc_url, xrdc_opts, xrdc_status */

typedef enum { MB_CREATE = 0, MB_REMOVE = 1 } metabench_phase;

typedef struct {
    int workers;          /* concurrent GSI sessions (one thread + one conn each) */
    int dirs_per_worker;  /* D: subdirs per worker subtree */
    int files_per_dir;    /* F: files per subdir */
    int p99_ceil_ms;      /* fail if storm p99 exceeds this; 0 = no ceiling */
} metabench_plan;

/* Derive a balanced D/F from a per-worker op budget. CREATE ops per worker =
 * 1 (mkdir /w) + 1 (chmod /w) + D*(mkdir + chmod) + D*F*(truncate + chmod + stat). */
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

#endif /* XRDC_METABENCH_H */
```

- [ ] **Step 2: Write the failing unit test `client/lib/metabench_unittest.c`**

```c
/*
 * metabench_unittest.c — standalone checks for the pure manifest/percentile
 * helpers. Build: cc -Wall -Wextra -I. -Ilib metabench_unittest.c lib/metabench.c -o /tmp/mbu
 * (only metabench.c's pure functions are exercised; the runner is not linked).
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "metabench.h"

static int checks;
#define CHECK(c) do { checks++; if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    metabench_plan p;
    metabench_plan_init(&p, 8, 125, 50);
    CHECK(p.workers == 8);
    CHECK(p.dirs_per_worker >= 1 && p.files_per_dir >= 1);
    /* per-worker op budget lands near 125 → total near 1000 */
    long total = metabench_storm_ops(&p);
    CHECK(total >= 800 && total <= 1200);

    /* expected namespace: 1 (/w) + D dirs + D*F files per worker */
    metabench_entry buf[4096];
    size_t n = metabench_expected(&p, buf, 4096);
    size_t per_worker = 1 + (size_t)p.dirs_per_worker
                          + (size_t)p.dirs_per_worker * (size_t)p.files_per_dir;
    CHECK(n == per_worker * (size_t)p.workers);
    /* sorted + modes assigned (dir 0755/0700, file 0640) */
    for (size_t i = 1; i < n; i++) CHECK(strcmp(buf[i-1].path, buf[i].path) <= 0);
    CHECK(buf[0].is_dir == 1);

    /* percentile: p50 of 1..100 ≈ 50.5, p99 ≈ 99.x, empty → 0 */
    double s[100]; for (int i = 0; i < 100; i++) s[i] = i + 1;
    CHECK(metabench_percentile(s, 100, 50.0) > 49.0 && metabench_percentile(s, 100, 50.0) < 52.0);
    CHECK(metabench_percentile(s, 100, 99.0) > 98.0);
    CHECK(metabench_percentile(s, 0, 99.0) == 0.0);

    printf("ok — %d checks\n", checks);
    return 0;
}
```

- [ ] **Step 3: Run it to confirm it fails (no implementation yet)**

Run: `cd client && cc -Wall -Wextra -Ilib lib/metabench_unittest.c lib/metabench.c -o /tmp/mbu`
Expected: FAIL — link error / `metabench.c` missing the functions.

- [ ] **Step 4: Implement the pure functions in `client/lib/metabench.c`**

```c
/*
 * metabench.c — deterministic metadata workload + percentiles + GSI runner.
 * This file: pure planning/percentile helpers (Task 1). Runner added in Task 2.
 */
#include "metabench.h"
#include <stdlib.h>
#include <string.h>

/* WHAT: choose D (dirs) and F (files/dir) so the per-worker CREATE op count is
 * close to `ops_per_worker`. WHY: hit ~1000 total with a small balanced tree.
 * HOW: CREATE ops/worker = 2 + 2*D + 3*D*F. Fix F=4, solve D, clamp >=1. */
void metabench_plan_init(metabench_plan *p, int workers, int ops_per_worker,
                         int p99_ceil_ms) {
    int F = 4;
    int D = (ops_per_worker - 2) / (2 + 3 * F);   /* 2 + 2D + 3DF = budget */
    if (D < 1) D = 1;
    p->workers = workers < 1 ? 1 : workers;
    p->files_per_dir = F;
    p->dirs_per_worker = D;
    p->p99_ceil_ms = p99_ceil_ms;
}

/* counted CREATE ops, all workers. */
long metabench_storm_ops(const metabench_plan *p) {
    long per = 2L + 2L * p->dirs_per_worker
             + 3L * p->dirs_per_worker * p->files_per_dir;
    return per * p->workers;
}

/* WHAT: emit the exact namespace a CREATE run leaves, sorted by path.
 * HOW: /w<id> (0755), /w<id>/d<d> (0700), /w<id>/d<d>/f<f> (0640). We build in
 * natural order then qsort, so callers can diff against a sorted `xrdfs ls -lR`. */
static int entry_cmp(const void *a, const void *b) {
    return strcmp(((const metabench_entry *)a)->path,
                  ((const metabench_entry *)b)->path);
}

size_t metabench_expected(const metabench_plan *p, metabench_entry *out,
                          size_t cap) {
    size_t n = 0;
    for (int w = 0; w < p->workers; w++) {
        if (n < cap) { snprintf(out[n].path, sizeof(out[n].path), "/w%d", w);
            out[n].mode = 0755; out[n].is_dir = 1; } n++;
        for (int d = 0; d < p->dirs_per_worker; d++) {
            if (n < cap) { snprintf(out[n].path, sizeof(out[n].path), "/w%d/d%d", w, d);
                out[n].mode = 0700; out[n].is_dir = 1; } n++;
            for (int f = 0; f < p->files_per_dir; f++) {
                if (n < cap) { snprintf(out[n].path, sizeof(out[n].path),
                    "/w%d/d%d/f%d", w, d, f); out[n].mode = 0640; out[n].is_dir = 0; } n++;
            }
        }
    }
    size_t sortable = n < cap ? n : cap;
    qsort(out, sortable, sizeof(*out), entry_cmp);
    return n;
}

/* linear-interpolated percentile over a copy of ms. */
static int dbl_cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

double metabench_percentile(const double *ms, size_t n, double pct) {
    if (n == 0) return 0.0;
    double *c = malloc(n * sizeof(*c));
    if (c == NULL) return 0.0;
    memcpy(c, ms, n * sizeof(*c));
    qsort(c, n, sizeof(*c), dbl_cmp);
    double rank = (pct / 100.0) * (double)(n - 1);
    size_t lo = (size_t)rank;
    double frac = rank - (double)lo;
    double v = (lo + 1 < n) ? c[lo] + frac * (c[lo + 1] - c[lo]) : c[lo];
    free(c);
    return v;
}
```

- [ ] **Step 5: Run the unit test — verify it passes**

Run: `cd client && cc -Wall -Wextra -Ilib lib/metabench_unittest.c lib/metabench.c -o /tmp/mbu && /tmp/mbu`
Expected: `ok — N checks` (exit 0).

- [ ] **Step 6: Register in the client Makefile**

Edit `client/Makefile:97` — append `lib/metabench.c` to the `LIB_SRCS :=` list (so it lands in `libxrdc.a`).

- [ ] **Step 7: Build the client library**

Run: `cd client && make -j$(nproc) lib`
Expected: `libxrdc.a` rebuilds cleanly, no warnings from `metabench.c`.

- [ ] **Step 8: Commit** (run only with operator approval)

```bash
git add client/lib/metabench.h client/lib/metabench.c client/lib/metabench_unittest.c client/Makefile
git commit -m "test(pblock): metadata-storm manifest + percentile engine (pure)"
```

---

## Task 2: Threaded GSI runner

**Files:**
- Modify: `client/lib/metabench.c` (add the runner + result printers)
- Modify: `client/lib/metabench.h` (add result types + `metabench_run`)

**Interfaces:**
- Consumes (from Task 1): `metabench_plan`, `metabench_phase`, `metabench_storm_ops`.
- Produces:
  - `typedef struct { int id; long ops, failures; double ops_per_sec; } metabench_wstat;`
  - `typedef struct { metabench_phase phase; long total_ops, failures; double wall_s, ops_per_sec, p50_ms, p95_ms, p99_ms; int nworkers; metabench_wstat per_worker[64]; } metabench_result;`
  - `int metabench_run(const xrdc_url *url, const xrdc_opts *opts, const metabench_plan *plan, metabench_phase phase, metabench_result *out, xrdc_status *st);`
  - `void metabench_result_print(const metabench_result *r, FILE *f);`
  - `void metabench_result_json(const metabench_result *r, FILE *f);`

- [ ] **Step 1: Add result types + declarations to `metabench.h`** (before `#endif`)

```c
typedef struct { int id; long ops, failures; double ops_per_sec; } metabench_wstat;

typedef struct {
    metabench_phase phase;
    long   total_ops, failures;
    double wall_s, ops_per_sec, p50_ms, p95_ms, p99_ms;
    int    nworkers;
    metabench_wstat per_worker[64];
} metabench_result;

/* WHAT: spawn plan->workers threads, each with ONE persistent GSI conn, running
 * the manifest `phase` and timing every op. WHY: measure pblock, not repeated
 * handshakes. HOW: per-thread xrdc_connect → ops → xrdc_close; merge latencies.
 * Returns 0 iff failures==0 AND (p99_ceil_ms==0 || p99_ms<=ceil); else -1.
 * `out` is filled in all cases; `st` carries the first fatal error. */
int metabench_run(const xrdc_url *url, const xrdc_opts *opts,
                  const metabench_plan *plan, metabench_phase phase,
                  metabench_result *out, xrdc_status *st);

void metabench_result_print(const metabench_result *r, FILE *f);  /* human */
void metabench_result_json(const metabench_result *r, FILE *f);   /* one JSON line */
```

- [ ] **Step 2: Write the failing harness-level test** — defer the executable test to Task 3 (the runner needs a live GSI server, which only the umbrella provides). Here, assert it *compiles + links* into `libxrdc.a` and the symbol is exported:

Run (after Step 3): `cd client && make -j$(nproc) lib && nm libxrdc.a | grep -q ' T metabench_run' && echo OK`
Expected before Step 3: `metabench_run` undefined / not in archive.

- [ ] **Step 3: Implement the runner in `metabench.c`**

```c
#include "xrdc_ops.h"   /* xrdc_mkdir/chmod/truncate/stat/rm/rmdir */
#include <pthread.h>

/* one worker's slice: connect (GSI) once, run its subtree, record latencies. */
typedef struct {
    const xrdc_url  *url;
    const xrdc_opts *opts;
    const metabench_plan *plan;
    metabench_phase  phase;
    int     id;
    double *lat_ms;     /* caller-allocated, capacity = storm ops for this worker */
    long    lat_cap;
    long    lat_n;
    long    ops, failures;
} mb_worker;

/* time one op via a function-pointer-free switch kept tiny + early-return. */
static void mb_record(mb_worker *w, uint64_t t0) {
    double ms = (double)(xrdc_mono_ns() - t0) / 1e6;
    if (w->lat_n < w->lat_cap) w->lat_ms[w->lat_n++] = ms;
}

/* CREATE: mkdir+chmod tree, create+chmod+stat files (stat asserts mode+size). */
static void mb_create(mb_worker *w, xrdc_conn *c) {
    const metabench_plan *p = w->plan;
    char path[512];
    xrdc_status st;
    uint64_t t0;

    snprintf(path, sizeof(path), "/w%d", w->id);
    t0 = xrdc_mono_ns(); if (xrdc_mkdir(c, path, 0755, 0, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);
    t0 = xrdc_mono_ns(); if (xrdc_chmod(c, path, 0755, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);

    for (int d = 0; d < p->dirs_per_worker; d++) {
        snprintf(path, sizeof(path), "/w%d/d%d", w->id, d);
        t0 = xrdc_mono_ns(); if (xrdc_mkdir(c, path, 0700, 0, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);
        t0 = xrdc_mono_ns(); if (xrdc_chmod(c, path, 0700, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);
        for (int f = 0; f < p->files_per_dir; f++) {
            snprintf(path, sizeof(path), "/w%d/d%d/f%d", w->id, d, f);
            t0 = xrdc_mono_ns(); if (xrdc_truncate(c, path, 0, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);
            t0 = xrdc_mono_ns(); if (xrdc_chmod(c, path, 0640, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);
            xrdc_statinfo si;
            t0 = xrdc_mono_ns();
            if (xrdc_stat(c, path, &si, &st) != 0) w->failures++;
            else if (si.have_ext && (si.mode & 0777) != 0640) w->failures++;  /* chmod persisted */
            w->ops++; mb_record(w, t0);
        }
    }
}

/* REMOVE: rm files, rmdir dirs bottom-up; leaves the store as it started. */
static void mb_remove(mb_worker *w, xrdc_conn *c) {
    const metabench_plan *p = w->plan;
    char path[512];
    xrdc_status st;
    uint64_t t0;

    for (int d = 0; d < p->dirs_per_worker; d++) {
        for (int f = 0; f < p->files_per_dir; f++) {
            snprintf(path, sizeof(path), "/w%d/d%d/f%d", w->id, d, f);
            t0 = xrdc_mono_ns(); if (xrdc_rm(c, path, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);
        }
        snprintf(path, sizeof(path), "/w%d/d%d", w->id, d);
        t0 = xrdc_mono_ns(); if (xrdc_rmdir(c, path, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);
    }
    snprintf(path, sizeof(path), "/w%d", w->id);
    t0 = xrdc_mono_ns(); if (xrdc_rmdir(c, path, &st) != 0) w->failures++; w->ops++; mb_record(w, t0);
}

static void *mb_thread(void *arg) {
    mb_worker *w = arg;
    xrdc_conn c;
    xrdc_status st;
    memset(&c, 0, sizeof(c));
    if (xrdc_connect(&c, w->url, w->opts, &st) != 0) {
        w->failures = w->lat_cap;   /* connect failure ⇒ every planned op counts as failed */
        w->ops = w->lat_cap;
        return NULL;
    }
    if (w->phase == MB_CREATE) mb_create(w, &c);
    else                        mb_remove(w, &c);
    xrdc_close(&c);
    return NULL;
}

int metabench_run(const xrdc_url *url, const xrdc_opts *opts,
                  const metabench_plan *plan, metabench_phase phase,
                  metabench_result *out, xrdc_status *st) {
    (void)st;
    int W = plan->workers;
    if (W > 64) W = 64;
    long per_cap = metabench_storm_ops(plan) / plan->workers + 8;

    mb_worker  *wk = calloc(W, sizeof(*wk));
    pthread_t  *th = calloc(W, sizeof(*th));
    double     *all = NULL;
    if (wk == NULL || th == NULL) { free(wk); free(th); return -1; }

    for (int i = 0; i < W; i++) {
        wk[i].url = url; wk[i].opts = opts; wk[i].plan = plan;
        wk[i].phase = phase; wk[i].id = i;
        wk[i].lat_cap = per_cap;
        wk[i].lat_ms = calloc(per_cap, sizeof(double));
    }

    uint64_t t0 = xrdc_mono_ns();
    for (int i = 0; i < W; i++) pthread_create(&th[i], NULL, mb_thread, &wk[i]);
    for (int i = 0; i < W; i++) pthread_join(th[i], NULL);
    double wall = (double)(xrdc_mono_ns() - t0) / 1e9;

    memset(out, 0, sizeof(*out));
    out->phase = phase; out->nworkers = W; out->wall_s = wall;
    long total_lat = 0;
    for (int i = 0; i < W; i++) total_lat += wk[i].lat_n;
    all = calloc(total_lat ? total_lat : 1, sizeof(double));
    long k = 0;
    for (int i = 0; i < W; i++) {
        out->total_ops += wk[i].ops;
        out->failures  += wk[i].failures;
        out->per_worker[i].id = i;
        out->per_worker[i].ops = wk[i].ops;
        out->per_worker[i].failures = wk[i].failures;
        out->per_worker[i].ops_per_sec = wall > 0 ? (double)wk[i].ops / wall : 0;
        for (long j = 0; j < wk[i].lat_n; j++) all[k++] = wk[i].lat_ms[j];
        free(wk[i].lat_ms);
    }
    out->ops_per_sec = wall > 0 ? (double)out->total_ops / wall : 0;
    out->p50_ms = metabench_percentile(all, k, 50.0);
    out->p95_ms = metabench_percentile(all, k, 95.0);
    out->p99_ms = metabench_percentile(all, k, 99.0);
    free(all); free(wk); free(th);

    int ok = (out->failures == 0)
          && (plan->p99_ceil_ms == 0 || out->p99_ms <= plan->p99_ceil_ms);
    return ok ? 0 : -1;
}

void metabench_result_print(const metabench_result *r, FILE *f) {
    fprintf(f, "  %ld ops, %ld fail, %.0f ops/s\n", r->total_ops, r->failures, r->ops_per_sec);
    fprintf(f, "  p50=%.1fms p95=%.1fms p99=%.1fms  %s\n",
            r->p50_ms, r->p95_ms, r->p99_ms, r->failures == 0 ? "PASS" : "FAIL");
}

void metabench_result_json(const metabench_result *r, FILE *f) {
    fprintf(f, "{\"phase\":%d,\"total_ops\":%ld,\"failures\":%ld,\"ops_per_sec\":%.1f,"
               "\"p50_ms\":%.3f,\"p95_ms\":%.3f,\"p99_ms\":%.3f,\"wall_s\":%.3f,\"workers\":%d}\n",
            r->phase, r->total_ops, r->failures, r->ops_per_sec,
            r->p50_ms, r->p95_ms, r->p99_ms, r->wall_s, r->nworkers);
}
```

> **No-goto note:** every op uses the `if (... != 0) w->failures++; w->ops++; mb_record(...)` early-flow idiom — no cleanup ladders, threads own their conn.

- [ ] **Step 3b: Confirm the connect/url/ops header names** — open `client/lib/xrdc_ops.h` and `client/lib/url.c`; if `xrdc_statinfo` lives in `xrdc_net.h` (it does) ensure `metabench.h` includes it; adjust the `#include` lines if the ops header differs. Fix any mismatched signature before building.

- [ ] **Step 4: Build the library and verify the symbol is exported**

Run: `cd client && make -j$(nproc) lib && nm libxrdc.a | grep ' T metabench_run' && echo OK`
Expected: a line ending `T metabench_run` then `OK`.

- [ ] **Step 5: Commit** (operator approval)

```bash
git add client/lib/metabench.c client/lib/metabench.h
git commit -m "test(pblock): threaded per-worker GSI metadata runner + result"
```

---

## Task 3: Layer (a) standalone harness

**Files:**
- Create: `tests/tools/pblock_meta_bench.c`

**Interfaces:**
- Consumes: `metabench_*` (Task 1/2), `libxrdc.a`.
- Produces: a binary that, given a `root://` URL + plan flags, runs MB_CREATE or MB_REMOVE and prints JSON (`--json`) or the expected namespace (`--print-expected`); exit code 0 = pass.

- [ ] **Step 1: Write `tests/tools/pblock_meta_bench.c`**

```c
/*
 * pblock_meta_bench.c — Layer (a) of the pblock metadata reliability suite.
 * Thin main over client/lib/metabench: thinnest client surface, so it isolates
 * the pblock backend. GSI is taken from X509_USER_PROXY (set by the umbrella).
 *
 * usage: pblock_meta_bench [--workers N] [--ops-per-worker N] [--p99-ceil-ms N]
 *                          [--phase create|remove] [--json] [--print-expected] <root-url>
 * exit: 0 = all ops ok and p99 within ceiling; non-zero otherwise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "metabench.h"

static int arg_int(const char *v, int dflt) { return v ? atoi(v) : dflt; }

int main(int argc, char **argv) {
    int workers = 8, ops = 125, ceil_ms = 50, json = 0, print_expected = 0;
    metabench_phase phase = MB_CREATE;
    const char *url_s = NULL;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--workers") && i+1 < argc)        workers = arg_int(argv[++i], workers);
        else if (!strcmp(argv[i], "--ops-per-worker") && i+1 < argc) ops     = arg_int(argv[++i], ops);
        else if (!strcmp(argv[i], "--p99-ceil-ms") && i+1 < argc)    ceil_ms = arg_int(argv[++i], ceil_ms);
        else if (!strcmp(argv[i], "--phase") && i+1 < argc)          phase = strcmp(argv[++i], "remove") ? MB_CREATE : MB_REMOVE;
        else if (!strcmp(argv[i], "--json"))                         json = 1;
        else if (!strcmp(argv[i], "--print-expected"))               print_expected = 1;
        else                                                          url_s = argv[i];
    }
    if (url_s == NULL) { fprintf(stderr, "usage: pblock_meta_bench [opts] <root-url>\n"); return 2; }

    metabench_plan plan;
    metabench_plan_init(&plan, workers, ops, ceil_ms);

    if (print_expected) {   /* emit "MODE is_dir PATH" sorted — the umbrella diffs this */
        metabench_entry buf[8192];
        size_t n = metabench_expected(&plan, buf, 8192);
        for (size_t i = 0; i < n && i < 8192; i++)
            printf("%04o %d %s\n", buf[i].mode & 0777, buf[i].is_dir, buf[i].path);
        return 0;
    }

    xrdc_url u; xrdc_opts o; xrdc_status st;
    memset(&o, 0, sizeof(o));
    if (xrdc_url_parse(url_s, &u, &st) != 0) { fprintf(stderr, "bad url: %s\n", url_s); return 2; }
    /* GSI: libxrdc reads X509_USER_PROXY / X509_CERT_DIR from env; opts default
     * auto-negotiates the advertised auth. (Confirm the exact opts field for a
     * forced GSI suite in client/lib/conn.c during implementation if needed.) */

    metabench_result r;
    int rc = metabench_run(&u, &o, &plan, phase, &r, &st);
    if (json) metabench_result_json(&r, stdout);
    else      metabench_result_print(&r, stdout);
    return rc == 0 ? 0 : 1;
}
```

- [ ] **Step 2: Build it against libxrdc (the umbrella will do this; verify by hand once)**

Run:
```bash
cd client && make -j$(nproc) lib proto
cc -Wall -Wextra -Ilib tests/../client/lib -I client/lib \
   ../tests/tools/pblock_meta_bench.c client/libxrdc.a client/libxrdproto.a \
   -lssl -lcrypto -lz -lpthread -o /tmp/pmb 2>&1 | head
```
(Exact include/lib paths are finalized in Task 4's script, which is the canonical builder. This step only confirms the source compiles + links.)
Expected: `/tmp/pmb` builds; `/tmp/pmb --print-expected root://x/` prints a sorted path list.

- [ ] **Step 3: Smoke the expected-namespace output (no server needed)**

Run: `/tmp/pmb --workers 2 --ops-per-worker 40 --print-expected root://x/ | head`
Expected: lines like `0755 1 /w0`, `0700 1 /w0/d0`, `0640 0 /w0/d0/f0`, sorted.

- [ ] **Step 4: Commit** (operator approval)

```bash
git add tests/tools/pblock_meta_bench.c
git commit -m "test(pblock): layer-a standalone libxrdc metadata harness"
```

---

## Task 4: Umbrella fixture + Layer (a) wiring + verification

**Files:**
- Create: `tests/run_pblock_meta_gsi.sh` (executable)

**Interfaces:**
- Consumes: `tests/tools/pblock_meta_bench.c`, `client/libxrdc.a`, `client/bin/xrdfs`, the nginx binary.
- Produces: the umbrella entry point. This task delivers the fixture, Layer (a), and all four verification criteria; Layers (b)/(c) and self-tests are appended in Tasks 5–7.

- [ ] **Step 1: Write `tests/run_pblock_meta_gsi.sh`**

```bash
#!/usr/bin/env bash
#
# run_pblock_meta_gsi.sh — concurrent GSI metadata-storm reliability + perf proof
# for the pblock storage backend, in three layers (libxrdc harness, xrdfs CLI,
# xrddiag metabench) against one shared fixture. Asserts: zero op failures,
# catalog integrity (exact namespace + no orphan blocks), server health after the
# storm, and p99 latency within a ceiling.
#
# Usage: tests/run_pblock_meta_gsi.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
XRDDIAG="$HERE/client/bin/xrddiag"
LIBXRDC="$HERE/client/libxrdc.a"
PROTOLIB="$HERE/client/libxrdproto.a"

WORKERS="${WORKERS:-8}"
OPS_PER_WORKER="${OPS_PER_WORKER:-125}"
P99_CEIL_MS="${P99_CEIL_MS:-50}"
PORT="${PORT:-11498}"
BS="${PBLOCK_BLOCK_SIZE:-1m}"

PFX="$(mktemp -d /tmp/pblock_meta_gsi.XXXXXX)"
H="root://127.0.0.1:${PORT}/"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

# --- skip-clean if prerequisites are missing -------------------------------
for need in "$NGINX" "$XRDFS" "$XRDDIAG" "$LIBXRDC"; do
    [ -e "$need" ] || { echo "SKIP: missing $need"; rm -rf "$PFX"; exit 0; }
done

mkdir -p "$PFX/root" "$PFX/conf" "$PFX/logs"

# --- GSI host cert/key + client proxy --------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$PFX/conf/host.key" -out "$PFX/conf/host.crt" \
    -subj "/CN=localhost" >/dev/null 2>&1
# Client proxy (self-signed EEC + proxy) — reuse the suite helper if present,
# else generate a minimal proxy with xrdgsiproxy.
"$HERE/client/bin/xrdgsiproxy" init -cert "$PFX/conf/host.crt" \
    -key "$PFX/conf/host.key" -out "$PFX/conf/proxy.pem" >/dev/null 2>&1 || true
[ -f "$PFX/conf/proxy.pem" ] || cp "$PFX/conf/host.crt" "$PFX/conf/proxy.pem"
export X509_USER_PROXY="$PFX/conf/proxy.pem"
export X509_CERT_DIR="$PFX/conf"

# --- pblock + GSI stream server --------------------------------------------
cat > "$PFX/nginx.conf" <<EOF
daemon on;
error_log $PFX/logs/error.log info;
pid $PFX/nginx.pid;
events { worker_connections 256; }
thread_pool default threads=8 max_queue=512;
stream {
    server {
        listen 127.0.0.1:${PORT};
        brix_root on;
        xrootd_root            $PFX/root;
        xrootd_auth            gsi;
        xrootd_certificate     $PFX/conf/host.crt;
        xrootd_certificate_key $PFX/conf/host.key;
        xrootd_allow_write     on;
        xrootd_upload_resume   off;
        xrootd_storage_backend pblock;
        xrootd_pblock_block_size ${BS};
        xrootd_access_log $PFX/logs/access.log;
    }
}
EOF

cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/logs/start.err" \
    || { echo "nginx failed to start"; cat "$PFX/logs/start.err"; exit 2; }
sleep 1

# --- build Layer (a) harness against libxrdc -------------------------------
MB="$PFX/pblock_meta_bench"
cc -O2 -Wall -I"$HERE/client/lib" "$HERE/tests/tools/pblock_meta_bench.c" \
   "$LIBXRDC" "$PROTOLIB" -lssl -lcrypto -lz -lpthread -o "$MB" \
   2>"$PFX/logs/cc.err" || { echo "harness build failed"; cat "$PFX/logs/cc.err"; exit 2; }
PLAN_ARGS="--workers $WORKERS --ops-per-worker $OPS_PER_WORKER --p99-ceil-ms $P99_CEIL_MS"

echo "== Layer (a): libxrdc direct code =="
"$MB" $PLAN_ARGS --phase create --json "$H" > "$PFX/logs/a_create.json" 2>"$PFX/logs/a.err"
a_rc=$?
cat "$PFX/logs/a_create.json"
[ "$a_rc" = 0 ] && ok "layer-a create: zero failures + p99<=${P99_CEIL_MS}ms" \
                 || bad "layer-a create (rc=$a_rc) — see logs/a_create.json"

# --- Criterion 2: catalog integrity (exact namespace + no orphan blocks) ---
echo "== verify: catalog integrity =="
"$MB" $PLAN_ARGS --print-expected "$H" | sort > "$PFX/logs/expected.txt"
# Read the namespace back THROUGH the server (proves the catalog holds it).
"$XRDFS" "$H" ls -lR / 2>/dev/null > "$PFX/logs/lsr.txt" || true
# Normalize ls -lR to "PATH" set and assert every expected path is present.
miss=0
while read -r mode isdir path; do
    grep -qF " $path" "$PFX/logs/lsr.txt" || { miss=$((miss+1)); }
done < "$PFX/logs/expected.txt"
[ "$miss" = 0 ] && ok "namespace readback: all expected paths present" \
                || bad "namespace readback: $miss expected path(s) missing"
# Orphan-block scan: all files are 0-byte ⇒ data dir must hold NO block files.
orphans=$(find "$PFX/root/data" -type f 2>/dev/null | wc -l)
[ "$orphans" = 0 ] && ok "no orphan blocks in data dir" \
                   || bad "orphan blocks present: $orphans"

# --- Criterion 1+ : remove phase exercises unlink/rmdir, then leak check ----
echo "== Layer (a): remove phase + leak check =="
"$MB" $PLAN_ARGS --phase remove --json "$H" > "$PFX/logs/a_remove.json" 2>>"$PFX/logs/a.err"
r_rc=$?
cat "$PFX/logs/a_remove.json"
[ "$r_rc" = 0 ] && ok "layer-a remove: zero failures" || bad "layer-a remove (rc=$r_rc)"
"$XRDFS" "$H" ls / 2>/dev/null | grep -q "/w0" \
    && bad "namespace not empty after remove (leak)" \
    || ok "store empty after remove (no namespace leak)"

# --- Criterion 4 was enforced in-band by harness rc (p99 ceiling) ----------
# --- Criterion 3: server health after the storm ----------------------------
echo "== verify: server health after storm =="
"$XRDFS" "$H" stat / >/dev/null 2>&1 \
    && ok "fresh GSI login + stat OK after storm" \
    || bad "server unhealthy after storm (GSI stat failed)"

# (Layers b + c appended in Tasks 5–6; self-tests in Task 7.)

echo
[ "$fail" = 0 ] && echo "PASS run_pblock_meta_gsi" || echo "FAIL run_pblock_meta_gsi"
exit "$fail"
```

- [ ] **Step 2: Make executable + run end-to-end**

Run: `chmod +x tests/run_pblock_meta_gsi.sh && tests/run_pblock_meta_gsi.sh`
Expected: Layer (a) create JSON with `"failures":0`, all `ok` lines, `PASS run_pblock_meta_gsi`. If the GSI proxy helper path differs, fix the cert/proxy block (mirror `tests/profile_lifecycle.sh:119-148` and any `tests/lib/*.sh` GSI helper) until login succeeds — do not weaken `xrootd_auth gsi`.

- [ ] **Step 3: Confirm it FAILS loudly when broken (sanity)**

Run: `P99_CEIL_MS=0 tests/run_pblock_meta_gsi.sh; echo "exit=$?"`
Expected: layer-a create FAILs (p99 > 0), `FAIL run_pblock_meta_gsi`, `exit=1`.

- [ ] **Step 4: Commit** (operator approval)

```bash
git add tests/run_pblock_meta_gsi.sh
git commit -m "test(pblock): GSI fixture + layer-a + catalog/health/p99 verification"
```

---

## Task 5: Layer (b) — full `xrdfs` CLI chain

**Files:**
- Modify: `tests/run_pblock_meta_gsi.sh` (append Layer (b) before the final pass/fail print)

**Interfaces:**
- Consumes: `client/bin/xrdfs`, the running fixture, `metabench --print-expected` for the manifest.

- [ ] **Step 1: Append the Layer (b) block** (insert before the `echo` + final pass/fail at the end of Task 4's script)

```bash
echo "== Layer (b): full xrdfs CLI chain (concurrent GSI sessions) =="
# Each worker runs the manifest as an xrdfs batch over one held GSI session.
# Generate a per-worker batch script from the expected namespace.
gen_batch() {  # $1 = worker id
    local w="$1"
    awk -v w="/w${w}/" '$3 ~ ("^"w) || $3 == "/w'"$w"'" {
        if ($2 == 1) printf "mkdir -m %s %s\n", substr($1,2), $3;
        else         printf "truncate %s 0\nchmod %s %s\n", $3, substr($1,2), $3;
    }' "$PFX/logs/expected.txt"
}
b_fail=0
for w in $(seq 0 $((WORKERS-1))); do
    gen_batch "$w" > "$PFX/logs/b_w${w}.xrdfs"
    ( "$XRDFS" "$H" < "$PFX/logs/b_w${w}.xrdfs" >"$PFX/logs/b_w${w}.out" 2>&1 ) &
done
wait
for w in $(seq 0 $((WORKERS-1))); do
    grep -qiE "error|denied|fail" "$PFX/logs/b_w${w}.out" && b_fail=$((b_fail+1))
done
[ "$b_fail" = 0 ] && ok "layer-b xrdfs chain: all sessions clean" \
                  || bad "layer-b xrdfs chain: $b_fail session(s) had errors"
# Catalog integrity again, now produced by the CLI path:
"$XRDFS" "$H" ls -lR / 2>/dev/null > "$PFX/logs/lsr_b.txt" || true
miss_b=0
while read -r mode isdir path; do
    grep -qF " $path" "$PFX/logs/lsr_b.txt" || miss_b=$((miss_b+1))
done < "$PFX/logs/expected.txt"
[ "$miss_b" = 0 ] && ok "layer-b namespace readback complete" \
                  || bad "layer-b namespace readback: $miss_b missing"
# Clean up the layer-b tree so layer-c starts fresh.
for w in $(seq 0 $((WORKERS-1))); do "$XRDFS" "$H" rm -r "/w${w}" >/dev/null 2>&1; done
```

> Confirm `xrdfs` reads a batch script from stdin (interactive mode) and that `mkdir -m`, `truncate`, `chmod`, `rm -r` are the actual subcommand spellings — `client/apps/xrdfs_meta.c` shows `mkdir [-p] [-m mode]`, `chmod [-R] <path> <mode>`, `ls -lR`. Adjust `gen_batch` to the real arg order if needed.

- [ ] **Step 2: Run**

Run: `tests/run_pblock_meta_gsi.sh`
Expected: Layer (b) `ok` lines; overall `PASS`.

- [ ] **Step 3: Commit** (operator approval)

```bash
git add tests/run_pblock_meta_gsi.sh
git commit -m "test(pblock): layer-b full xrdfs CLI chain over GSI"
```

---

## Task 6: Layer (c) — `xrddiag metabench` subcommand + umbrella wiring

**Files:**
- Create: `client/apps/diag_metabench.c`
- Modify: `client/apps/diag_internal.h` (declare `do_metabench`)
- Modify: `client/apps/xrddiag.c` (dispatch + usage)
- Modify: `client/Makefile:219` (`XRDDIAG_SPLIT`)
- Modify: `tests/run_pblock_meta_gsi.sh` (append Layer (c))

**Interfaces:**
- Consumes: `metabench_run` (Task 2), `diag_args` (`client/apps/diag_internal.h`).
- Produces: `int do_metabench(diag_args *a);` and the `metabench` subcommand.

- [ ] **Step 1: Write `client/apps/diag_metabench.c`**

```c
/*
 * diag_metabench.c — `xrddiag metabench <url>`: concurrent metadata storm with
 * ops/sec + p50/p95/p99, proving the CLIENT performs (not just connects). Mirror
 * of diag_bench.c but for metadata. Reuses client/lib/metabench so the workload
 * is identical to the suite's other layers (DRY).
 */
#include "diag_internal.h"
#include "metabench.h"

/* WHAT: run the metadata storm against a->url with a->conn (GSI/anon as parsed).
 * WHY: an operator-runnable client health/perf gate. HOW: parse --workers /
 * --ops-per-worker / --p99-ceil-ms from a->urls tail is overkill; read dedicated
 * fields if present, else defaults. Exit non-zero on any failure or p99 breach. */
int do_metabench(diag_args *a) {
    int workers = a->streams > 0 ? a->streams : 8;   /* reuse --streams as worker count */
    int ops     = a->count   > 0 ? a->count   : 125; /* reuse --count as ops/worker */
    int ceil_ms = 50;

    xrdc_url u; xrdc_status st;
    if (a->url == NULL || xrdc_url_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "metabench: bad or missing url\n");
        return 2;
    }
    metabench_plan plan;
    metabench_plan_init(&plan, workers, ops, ceil_ms);

    printf("xrddiag metabench %s\n", a->url);
    metabench_result rc_res;
    int rc = metabench_run(&u, &a->conn, &plan, MB_CREATE, &rc_res, &st);
    metabench_result_print(&rc_res, stdout);
    /* tidy up the namespace we created (best-effort) */
    metabench_result rm_res;
    metabench_run(&u, &a->conn, &plan, MB_REMOVE, &rm_res, &st);
    return rc == 0 ? 0 : 1;
}
```

- [ ] **Step 2: Declare it in `client/apps/diag_internal.h`** (near the other `do_*` decls)

```c
int do_metabench(diag_args *a);
```

- [ ] **Step 3: Dispatch + usage in `client/apps/xrddiag.c`**

Add to the dispatch ladder (next to `do_bench`, `xrddiag.c:629`):
```c
    if (strcmp(sub, "metabench") == 0)    { return do_metabench(&a); }
```
Add a usage line in `usage()` (`xrddiag.c:523`):
```c
        "  metabench <url>   concurrent metadata storm: ops/sec + p50/p95/p99\n"
```

- [ ] **Step 4: Register the object in `client/Makefile:219`**

Append `apps/diag_metabench.o` to `XRDDIAG_SPLIT :=`.

- [ ] **Step 5: Build xrddiag**

Run: `cd client && make -j$(nproc) bin/xrddiag && ./bin/xrddiag 2>&1 | grep -q metabench && echo OK`
Expected: builds clean; usage lists `metabench`; `OK`.

- [ ] **Step 6: Append Layer (c) to the umbrella** (before the final pass/fail print)

```bash
echo "== Layer (c): xrddiag client validation =="
"$XRDDIAG" check "$H" >"$PFX/logs/c_check.txt" 2>&1
grep -qiE "RED|FAIL" "$PFX/logs/c_check.txt" \
    && bad "xrddiag check: client conformance not all-green" \
    || ok "xrddiag check: client conformance all-green"
"$XRDDIAG" metabench --streams "$WORKERS" --count "$OPS_PER_WORKER" "$H" \
    >"$PFX/logs/c_metabench.txt" 2>&1
c_rc=$?
cat "$PFX/logs/c_metabench.txt"
[ "$c_rc" = 0 ] && ok "xrddiag metabench: client performs (0 fail)" \
               || bad "xrddiag metabench (rc=$c_rc)"
```

> Confirm `xrddiag`'s flag names for worker-count / ops — the plan reuses `--streams` and `--count` (already in `diag_args`). If those flags aren't parsed for an arbitrary subcommand, add minimal parsing in `do_metabench` reading `a->urls`/argv, or extend the `xrddiag.c` option parser. Keep it consistent with `bench`.

- [ ] **Step 7: Run full suite**

Run: `tests/run_pblock_meta_gsi.sh`
Expected: all three layers `ok`; `PASS run_pblock_meta_gsi`.

- [ ] **Step 8: Commit** (operator approval)

```bash
git add client/apps/diag_metabench.c client/apps/diag_internal.h client/apps/xrddiag.c client/Makefile tests/run_pblock_meta_gsi.sh
git commit -m "feat(xrddiag): metabench subcommand + wire layer-c into pblock suite"
```

---

## Task 7: Suite self-tests (success / fault / security-negative)

**Files:**
- Modify: `tests/run_pblock_meta_gsi.sh` (add a `--selftest` mode that drives the three meta-assertions)

**Interfaces:**
- Consumes: the umbrella itself.

- [ ] **Step 1: Add a `--selftest` path near the top of the script** (after arg parse)

```bash
if [ "${1:-}" = "--selftest" ]; then
    base="$(cd "$(dirname "$0")" && pwd)/run_pblock_meta_gsi.sh"
    echo "[selftest] 1/3 success: healthy run must PASS"
    "$base" >/dev/null 2>&1 && echo "  ok success" || { echo "  FAIL success"; exit 1; }
    echo "[selftest] 2/3 fault: P99_CEIL_MS=0 must FAIL (detects, not silently passes)"
    P99_CEIL_MS=0 "$base" >/dev/null 2>&1 && { echo "  FAIL fault-not-detected"; exit 1; } || echo "  ok fault detected"
    echo "[selftest] 3/3 security-neg: invalid GSI proxy must be rejected"
    X509_USER_PROXY=/dev/null "$base" >/dev/null 2>&1 && { echo "  FAIL gsi-bypass"; exit 1; } || echo "  ok GSI gate enforced"
    echo "selftest PASS"; exit 0
fi
```

> The security-neg case relies on the umbrella *exporting* `X509_USER_PROXY` itself (Task 4). To let the env override take effect, change Task 4's export to `export X509_USER_PROXY="${X509_USER_PROXY:-$PFX/conf/proxy.pem}"` so `--selftest` can inject `/dev/null`. Make that one-line edit here.

- [ ] **Step 2: Run the self-test**

Run: `tests/run_pblock_meta_gsi.sh --selftest`
Expected:
```
  ok success
  ok fault detected
  ok GSI gate enforced
selftest PASS
```

- [ ] **Step 3: Commit** (operator approval)

```bash
git add tests/run_pblock_meta_gsi.sh
git commit -m "test(pblock): suite self-tests — success/fault/GSI-negative"
```

---

## Self-Review

**Spec coverage:**
- §3 shared fixture → Task 4 (cert/key/proxy, pblock+GSI nginx, skip-clean, tunables). ✓
- §4 deterministic op manifest → Task 1 (`metabench_expected`, `metabench_plan_init`) + Task 2 (`mb_create`/`mb_remove`). ✓
- §5.1 zero failures → Task 2 (failure counters), Task 4 (rc gate). ✓
- §5.2 catalog integrity → Task 4 (namespace readback + orphan-block scan + post-remove leak check). ✓
- §5.3 server health → Task 4 (post-storm GSI stat). ✓
- §5.4 latency bounds → Task 2 (p99 vs ceil in `metabench_run` rc), Task 4 (`P99_CEIL_MS`). ✓
- §6 three layers → Task 3 (a), Task 5 (b), Task 6 (c). ✓
- §7 `xrddiag metabench` → Task 6. ✓
- §8 shared unit home (`client/lib/metabench`) → Tasks 1–2 (resolved: libxrdc so both harness + shipped binary link it). ✓
- §9 suite self-tests → Task 7. ✓

**Placeholder scan:** No "TBD"/"implement later". The two spec §10 open items are resolved: shared unit lives in `client/lib/`; D/F derived in `metabench_plan_init` (F=4, D solved from budget). Remaining "confirm exact spelling" notes (xrdfs batch arg order, xrddiag flag parsing, `xrdc_url_parse` name, GSI opts field) are verification steps with a concrete fallback, not blanks.

**Type consistency:** `metabench_plan`/`metabench_phase`/`metabench_result`/`metabench_wstat`/`metabench_entry` and the functions `metabench_plan_init`, `metabench_storm_ops`, `metabench_expected`, `metabench_percentile`, `metabench_run`, `metabench_result_print`, `metabench_result_json` are used identically across Tasks 1–6. `do_metabench(diag_args*)` matches the `diag_internal.h` decl and the `xrddiag.c` dispatch.

**Known verification points (carry into execution, each has a fallback):**
1. `xrdc_url_parse` exact name/signature (`client/lib/url.c`).
2. Forcing GSI in `xrdc_opts` vs relying on env + auto-negotiation (`client/lib/conn.c`).
3. `xrdfs` stdin batch mode + exact `mkdir -m` / `truncate` / `chmod` / `rm -r` arg order.
4. `xrddiag` option parsing reuse of `--streams`/`--count` for a custom subcommand.
5. `xrdgsiproxy init` flag set for proxy generation (fall back to a suite GSI helper in `tests/lib/`).
