/*
 * storascan_bench.c — xrdstorascan `bench` subcommand (B1).
 *
 * WHAT: a gateway throughput/latency probe — sweep block size × parallelism,
 *       report MiB/s + IOPS + latency p50/p95/p99 for read ops.
 * WHY:  answers "how fast is this librados/pblock gateway" with an object-
 *       store-shaped workload; split from xrdstorascan.c to keep each
 *       subcommand within the Phase-38 size budget.
 * HOW:  one pthread per worker per cell, each on its own libbrix connection;
 *       the pure percentile/throughput math lives in storascan_core.c. No goto.
 */
#include "storascan_core.h"
#include "storascan_internal.h"
#include "brix.h"
#include "brix_net.h"
#include "brix_ops.h"
#include "core/progname.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *url;
    brix_url    u;
    size_t      block;
    int         random;     /* 0 = sequential (wrap at EOF), 1 = random offset   */
    uint64_t    deadline_ns;/* 0 ⇒ use op_budget instead of time                 */
    uint64_t    op_budget;  /* this worker's op count when deadline_ns == 0      */
    int64_t     fsize;      /* file size, for offset selection                   */
    unsigned    seed;       /* per-worker PRNG state (rand_r — MT-safe)           */
    /* outputs */
    double     *lat_ms;
    size_t      lat_n;
    uint64_t    bytes;
    int         err;
    char        errmsg[STORASCAN_MSG];
} bench_worker;

/* Pick the next read offset for op index k, given file size and block.
 * Uses the worker's private rand_r seed so concurrent workers never share
 * PRNG state. */
static int64_t
bench_offset(bench_worker *w, uint64_t k)
{
    int64_t span = w->fsize - (int64_t) w->block;

    if (span <= 0) {
        return 0;
    }
    if (w->random) {
        uint64_t r = ((uint64_t) rand_r(&w->seed) << 16) ^
                     (uint64_t) rand_r(&w->seed);
        return (int64_t) (r % (uint64_t) (span + 1));
    }
    return (int64_t) ((k * (uint64_t) w->block) % (uint64_t) (span + 1));
}

static void *
bench_run(void *arg)
{
    bench_worker *w = (bench_worker *) arg;
    brix_conn     c;
    brix_status   st;
    brix_file     f;
    char         *buf;
    uint64_t      k = 0;

    brix_status_clear(&st);
    if (brix_connect(&c, &w->u, NULL, &st) != 0) {
        w->err = 1;
        snprintf(w->errmsg, sizeof(w->errmsg), "connect: %s", st.msg);
        return NULL;
    }
    if (brix_file_open_read(&c, w->u.path, &f, &st) != 0) {
        w->err = 1;
        snprintf(w->errmsg, sizeof(w->errmsg), "open: %s", st.msg);
        brix_close(&c);
        return NULL;
    }
    buf = (char *) malloc(w->block);
    if (buf == NULL) {
        w->err = 1;
        snprintf(w->errmsg, sizeof(w->errmsg), "out of memory");
        brix_file_close(&c, &f, &st);
        brix_close(&c);
        return NULL;
    }

    for (;;) {
        uint64_t t0, t1;
        int64_t  off;
        ssize_t  n;

        if (w->deadline_ns != 0) {
            if (brix_mono_ns() >= w->deadline_ns) {
                break;
            }
        } else if (k >= w->op_budget) {
            break;
        }

        off = bench_offset(w, k);
        t0 = brix_mono_ns();
        n = brix_file_read(&c, &f, off, buf, w->block, &st);
        t1 = brix_mono_ns();
        if (n < 0) {
            w->err = 1;
            snprintf(w->errmsg, sizeof(w->errmsg), "read: %s", st.msg);
            break;
        }
        if (w->lat_n < STORASCAN_LAT_CAP) {
            w->lat_ms[w->lat_n++] = (double) (t1 - t0) / 1.0e6;
        }
        w->bytes += (uint64_t) n;
        k++;
        if (n == 0) {            /* empty file: avoid a tight spin */
            break;
        }
    }

    free(buf);
    (void) brix_file_close(&c, &f, &st);
    brix_close(&c);
    return NULL;
}

/*
 * bench_cell_cfg_t — one (block, parallel) sweep cell's inputs.
 * WHY: bench_cell previously took 11 raw parameters; a named config keeps
 *      the callsite readable and the signature under the argument gate.
 */
typedef struct {
    const char     *url;         /* original URL string (worker context)     */
    const brix_url *u;           /* parsed endpoint workers reconnect to     */
    int64_t         fsize;       /* remote file size, for offset selection   */
    size_t          block;       /* read size for this cell                  */
    int             parallel;    /* worker/thread count                      */
    int             random;      /* 1 = random offsets, 0 = sequential       */
    uint64_t        duration_ns; /* time budget (0 ⇒ use total_ops)          */
    uint64_t        total_ops;   /* op budget across all workers             */
} bench_cell_cfg_t;

/*
 * bench_workers_free — release a cell's worker/thread arrays.
 * WHY: single owner for the alloc set (lat arrays + w + th) so every
 *      bench_cell exit path frees exactly once.
 * HOW: lat_ms slots are NULL-safe (calloc'd workers), so this is valid on
 *      partially-initialized cells too.
 */
static void
bench_workers_free(bench_worker *w, pthread_t *th, int parallel)
{
    int i;

    for (i = 0; i < parallel; i++) {
        free(w[i].lat_ms);
    }
    free(w);
    free(th);
}

/*
 * bench_workers_init — fill per-worker state + allocate latency buffers.
 * WHY: splits cell setup out of bench_cell's orchestration.
 * HOW: seeds each worker's private rand_r state, splits the op budget evenly
 *      and records the raw duration (rebased to a deadline in
 *      bench_workers_run). Any latency-buffer allocation failure reports
 *      "out of memory" and returns -1 (caller frees via bench_workers_free).
 */
static int
bench_workers_init(const bench_cell_cfg_t *cfg, bench_worker *w,
                   char *errmsg, size_t errsz)
{
    int i, rc = 0;

    for (i = 0; i < cfg->parallel; i++) {
        w[i].url = cfg->url;
        w[i].u = *cfg->u;
        w[i].block = cfg->block;
        w[i].random = cfg->random;
        w[i].fsize = cfg->fsize;
        w[i].seed = (unsigned) (brix_mono_ns() + (uint64_t) i * 2654435761u);
        w[i].deadline_ns = cfg->duration_ns;   /* rebased for time mode */
        w[i].op_budget = cfg->total_ops / (uint64_t) cfg->parallel;
        w[i].lat_ms = (double *) malloc(STORASCAN_LAT_CAP * sizeof(double));
        if (w[i].lat_ms == NULL) {
            snprintf(errmsg, errsz, "out of memory");
            rc = -1;
        }
    }
    return rc;
}

/*
 * bench_workers_run — spawn one thread per worker, join them all, time it.
 * WHY: isolates the thread lifecycle from setup and aggregation.
 * HOW: time mode rebases every worker's deadline to now + duration before
 *      the spawn loop; a failed pthread_create is recorded as that worker's
 *      error and its slot skipped at join. t0/t1 bracket the whole cell.
 */
static void
bench_workers_run(bench_worker *w, pthread_t *th, const bench_cell_cfg_t *cfg,
                  uint64_t *t0, uint64_t *t1)
{
    int i;

    *t0 = brix_mono_ns();
    if (cfg->duration_ns != 0) {
        uint64_t deadline = *t0 + cfg->duration_ns;
        for (i = 0; i < cfg->parallel; i++) {
            w[i].deadline_ns = deadline;
        }
    }
    for (i = 0; i < cfg->parallel; i++) {
        if (pthread_create(&th[i], NULL, bench_run, &w[i]) != 0) {
            w[i].err = 1;
            snprintf(w[i].errmsg, sizeof(w[i].errmsg), "pthread_create failed");
            th[i] = 0;
        }
    }
    for (i = 0; i < cfg->parallel; i++) {
        if (th[i] != 0) {
            pthread_join(th[i], NULL);
        }
    }
    *t1 = brix_mono_ns();
}

/*
 * bench_workers_error — surface any worker failure into errmsg.
 * WHY: keeps the "did any worker fail" sweep out of bench_cell.
 * HOW: scans all workers; the last failing worker's message wins (same as
 *      the pre-split behavior). Returns 0 clean / -1 on any error.
 */
static int
bench_workers_error(const bench_worker *w, int parallel,
                    char *errmsg, size_t errsz)
{
    int i, rc = 0;

    for (i = 0; i < parallel; i++) {
        if (w[i].err) {
            rc = -1;
            snprintf(errmsg, errsz, "worker %d: %.500s", i, w[i].errmsg);
        }
    }
    return rc;
}

/*
 * bench_workers_compute — merge per-worker samples into one result.
 * WHY: percentile math needs a single sorted sample array; the merge is a
 *      self-contained aggregation step.
 * HOW: sums bytes + sample counts, concatenates the per-worker latency
 *      arrays into one buffer and hands it to the pure statistics core.
 *      Returns -1 only when the merge buffer cannot be allocated.
 */
static int
bench_workers_compute(const bench_worker *w, const bench_cell_cfg_t *cfg,
                      uint64_t elapsed_ns, storascan_bench_result *out)
{
    double  *all_lat;
    size_t   all_n = 0, off = 0;
    uint64_t total_bytes = 0;
    int      i;

    for (i = 0; i < cfg->parallel; i++) {
        all_n += w[i].lat_n;
        total_bytes += w[i].bytes;
    }
    all_lat = (double *) malloc((all_n ? all_n : 1) * sizeof(double));
    if (all_lat == NULL) {
        return -1;
    }
    for (i = 0; i < cfg->parallel; i++) {
        memcpy(all_lat + off, w[i].lat_ms, w[i].lat_n * sizeof(double));
        off += w[i].lat_n;
    }
    storascan_bench_compute(all_lat, all_n, total_bytes,
                            (double) elapsed_ns / 1.0e9, out);
    free(all_lat);
    return 0;
}

/* Run one (block, parallel) cell; fill *out. Returns 0 / -1 (worker error). */
static int
bench_cell(const bench_cell_cfg_t *cfg, storascan_bench_result *out,
           char *errmsg, size_t errsz)
{
    bench_worker *w;
    pthread_t    *th;
    uint64_t      t0, t1;
    int           rc;

    w = (bench_worker *) calloc((size_t) cfg->parallel, sizeof(*w));
    th = (pthread_t *) calloc((size_t) cfg->parallel, sizeof(*th));
    if (w == NULL || th == NULL) {
        free(w);
        free(th);
        snprintf(errmsg, errsz, "out of memory");
        return -1;
    }
    if (bench_workers_init(cfg, w, errmsg, errsz) != 0) {
        bench_workers_free(w, th, cfg->parallel);
        return -1;
    }

    bench_workers_run(w, th, cfg, &t0, &t1);

    rc = bench_workers_error(w, cfg->parallel, errmsg, errsz);
    if (bench_workers_compute(w, cfg, t1 - t0, out) != 0) {
        rc = -1;
        snprintf(errmsg, errsz, "out of memory");
    }
    bench_workers_free(w, th, cfg->parallel);
    return rc;
}

/* Parse a comma-separated list of sizes/ints into out[]; returns count or -1. */
static int
parse_list(const char *s, int as_bytes, long *out, int max)
{
    char *copy = strdup(s);
    char *save = NULL;
    char *tok;
    int   n = 0;

    if (copy == NULL) {
        return -1;
    }
    for (tok = strtok_r(copy, ",", &save); tok != NULL && n < max;
         tok = strtok_r(NULL, ",", &save)) {
        long v = as_bytes ? (long) brix_parse_bytes(tok) : atol(tok);
        if (v <= 0) {
            free(copy);
            return -1;
        }
        out[n++] = v;
    }
    free(copy);
    return n;
}

/*
 * bench_args_t — decoded `bench` command line (defaults pre-filled by
 * cmd_bench, lists expanded by bench_validate_args).
 * WHY: lets parse / validate / run pass one state block instead of ten
 *      loose locals.
 */
typedef struct {
    const char *url;
    const char *block_s;                    /* raw --block list             */
    const char *par_s;                      /* raw --parallel list          */
    const char *pattern;                    /* "seq" | "random"             */
    long        duration_s;                 /* time budget (0 ⇒ count mode) */
    long        count;                      /* op budget (0 ⇒ time mode)    */
    int         json;
    long        blocks[STORASCAN_MAX_SWEEP];
    long        pars[STORASCAN_MAX_SWEEP];
    int         nblocks;
    int         npars;
} bench_args_t;

/*
 * bench_help — print the bench subcommand usage to stdout (WS-2).
 * WHY: --help as the first subcommand arg must exit cleanly to stdout.
 * HOW: one printf of the frozen usage text; returns SX_OK for the caller.
 */
static int
bench_help(const char *prog)
{
    printf("usage: %s bench <url> [--op read]\n"
           "                         [--block SZ[,SZ...]] [--parallel N[,N...]]\n"
           "                         [--duration S | --count N]\n"
           "                         [--pattern seq|random] [--json]\n"
           "    Throughput/latency sweep against the gateway. SZ accepts K/M/G.\n"
           "    defaults: --block 1M,4M --parallel 1,8 --duration 5 --pattern seq\n",
           prog);
    brix_usage_footer(stdout, prog);
    return SX_OK;
}

/*
 * bench_parse_args — decode `bench` options into *ba.
 * WHY: keeps cmd_bench a linear pipeline (parse → validate → sweep).
 * HOW: value-taking flags via opt_take; --duration and --count are mutually
 *      exclusive (last one wins, zeroing the other); exactly one positional
 *      URL; unknown options print usage → SX_USAGE.
 */
static int
bench_parse_args(int argc, char **argv, bench_args_t *ba, const char *prog)
{
    const char *v;
    int         i;

    for (i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (opt_take("--op", argc, argv, &i, &v)) {
            if (strcmp(v, "read") != 0) {
                fprintf(stderr, "xrdstorascan: bench phase 1 supports --op read only\n");
                return SX_USAGE;
            }
        } else if (opt_take("--block", argc, argv, &i, &ba->block_s)) {
        } else if (opt_take("--parallel", argc, argv, &i, &ba->par_s)) {
        } else if (opt_take("--duration", argc, argv, &i, &v)) {
            ba->duration_s = atol(v);
            ba->count = 0;
        } else if (opt_take("--count", argc, argv, &i, &v)) {
            ba->count = atol(v);
            ba->duration_s = 0;
        } else if (opt_take("--pattern", argc, argv, &i, &ba->pattern)) {
        } else if (strcmp(a, "--json") == 0) {
            ba->json = 1;
        } else if (a[0] == '-') {
            return usage(prog, SX_USAGE);
        } else if (ba->url == NULL) {
            ba->url = a;
        } else {
            return usage(prog, SX_USAGE);
        }
    }
    return SX_OK;
}

/*
 * bench_validate_args — check the parsed args and expand the sweep lists.
 * WHY: separates "is the command line sane" from option decoding.
 * HOW: requires a URL and a seq|random pattern, then expands the raw
 *      --block/--parallel strings into blocks[]/pars[] via parse_list.
 */
static int
bench_validate_args(bench_args_t *ba, const char *prog)
{
    if (ba->url == NULL) {
        return usage(prog, SX_USAGE);
    }
    if (strcmp(ba->pattern, "seq") != 0 && strcmp(ba->pattern, "random") != 0) {
        fprintf(stderr, "xrdstorascan: --pattern must be seq or random\n");
        return SX_USAGE;
    }
    ba->nblocks = parse_list(ba->block_s, 1, ba->blocks, STORASCAN_MAX_SWEEP);
    ba->npars = parse_list(ba->par_s, 0, ba->pars, STORASCAN_MAX_SWEEP);
    if (ba->nblocks <= 0 || ba->npars <= 0) {
        fprintf(stderr, "xrdstorascan: bad --block/--parallel list\n");
        return SX_USAGE;
    }
    return SX_OK;
}

/*
 * bench_render_cell — print one sweep cell (JSON line or table row).
 * WHY: keeps output formatting out of the sweep loop.
 * HOW: emits the frozen JSON object in --json mode, otherwise the frozen
 *      fixed-width table row.
 */
static void
bench_render_cell(const bench_args_t *ba, long block, long par,
                  const storascan_bench_result *r)
{
    if (ba->json) {
        printf("{\"t\":\"bench\",\"op\":\"read\",\"block\":%ld,"
               "\"parallel\":%ld,\"pattern\":\"%s\","
               "\"throughput_mibps\":%.2f,\"iops\":%.1f,"
               "\"p50_ms\":%.3f,\"p95_ms\":%.3f,\"p99_ms\":%.3f,"
               "\"ops\":%llu,\"bytes\":%llu}\n",
               block, par, ba->pattern,
               r->throughput_mibps, r->iops, r->p50_ms, r->p95_ms, r->p99_ms,
               (unsigned long long) r->ops, (unsigned long long) r->bytes);
    } else {
        printf("%-10ld %-8ld %14.2f %10.1f %9.3f %9.3f %9.3f\n",
               block, par, r->throughput_mibps, r->iops,
               r->p50_ms, r->p95_ms, r->p99_ms);
    }
}

/*
 * bench_run_matrix — run every (block × parallel) sweep cell.
 * WHY: the nested sweep is the run step of the bench pipeline; isolating it
 *      keeps cmd_bench under the complexity gate.
 * HOW: builds a bench_cell_cfg_t per cell; a failed cell is reported to
 *      stderr and marks the run SX_ERROR but the sweep continues.
 */
static int
bench_run_matrix(const bench_args_t *ba, const brix_url *u, int64_t fsize)
{
    int bi, pi;
    int rc = SX_OK;

    for (bi = 0; bi < ba->nblocks; bi++) {
        for (pi = 0; pi < ba->npars; pi++) {
            storascan_bench_result r;
            char             errmsg[STORASCAN_MSG] = {0};
            bench_cell_cfg_t cfg;

            cfg.url = ba->url;
            cfg.u = u;
            cfg.fsize = fsize;
            cfg.block = (size_t) ba->blocks[bi];
            cfg.parallel = (int) ba->pars[pi];
            cfg.random = strcmp(ba->pattern, "random") == 0;
            cfg.duration_ns = ba->duration_s > 0
                              ? (uint64_t) ba->duration_s * 1000000000ull : 0;
            cfg.total_ops = ba->count > 0 ? (uint64_t) ba->count : 0;

            if (bench_cell(&cfg, &r, errmsg, sizeof(errmsg)) != 0) {
                fprintf(stderr, "xrdstorascan: bench %ldx%ld: %s\n",
                        ba->blocks[bi], ba->pars[pi], errmsg);
                rc = SX_ERROR;
                continue;
            }
            bench_render_cell(ba, ba->blocks[bi], ba->pars[pi], &r);
        }
    }
    return rc;
}

int
cmd_bench(int argc, char **argv, const char *prog)
{
    bench_args_t  ba;
    int           rc;
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    brix_statinfo sti;

    /* --help as the first subcommand arg → print bench usage to stdout
     * and exit cleanly (WS-2). */
    if (argc >= 1 && strcmp(argv[0], "--help") == 0) {
        return bench_help(prog);
    }

    memset(&ba, 0, sizeof(ba));
    ba.block_s = "1M,4M";
    ba.par_s = "1,8";
    ba.pattern = "seq";
    ba.duration_s = 5;

    rc = bench_parse_args(argc, argv, &ba, prog);
    if (rc != SX_OK) {
        return rc;
    }
    rc = bench_validate_args(&ba, prog);
    if (rc != SX_OK) {
        return rc;
    }

    rc = storascan_connect(ba.url, &u, &c, &st);
    if (rc != SX_OK) {
        return rc;
    }
    if (brix_stat(&c, u.path, &sti, &st) != 0) {
        fprintf(stderr, "xrdstorascan: stat %s: %s\n", u.path, st.msg);
        brix_close(&c);
        return brix_shellcode(&st);
    }
    brix_close(&c);   /* workers open their own connections */

    if (!ba.json) {
        printf("# bench %s  size=%lld bytes  pattern=%s  %s\n",
               u.path, (long long) sti.size, ba.pattern,
               ba.count ? "count" : "duration");
        printf("%-10s %-8s %14s %10s %9s %9s %9s\n",
               "block", "parallel", "MiB/s", "IOPS", "p50_ms", "p95_ms", "p99_ms");
    }

    return bench_run_matrix(&ba, &u, sti.size);
}
