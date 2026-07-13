/*
 * xrdstorascan.c — backend-aware storage admin tool (clean-room C, libXrdCl-free).
 *
 * WHAT: the client front-end for the storage-scan feature set. Phase 1 ships the
 *       two client-side modes that need no server engine and work against any
 *       backend (POSIX / pblock / Ceph) over today's wire:
 *         verify <url>   end-to-end single-file integrity (A1): pull the bytes,
 *                        recompute the checksum, compare to the server's
 *                        kXR_Qcksum — catches at-rest *or* in-transit corruption.
 *         bench  <url>   gateway performance test (B1): sweep block size ×
 *                        parallelism, report throughput + IOPS + latency
 *                        p50/p95/p99 — "how fast is this librados/pblock gateway".
 *       Server-engine modes (inspect/inventory/drift/health) arrive in later
 *       phases (see docs/superpowers/specs/2026-06-29-client-backend-sysadmin-tooling-design.md).
 * WHY:  give sysadmins a one-command trust check for a single object and a
 *       realistic, object-store-shaped throughput/latency probe of their gateway.
 * HOW:  thin orchestration over libbrix (connect/open/read/query) + the pure
 *       statistics/verdict core in storascan_core.c. No libXrdCl, no goto.
 */
#include "storascan_core.h"
#include "brix.h"
#include "brix_net.h"
#include "brix_ops.h"
#include "core/version.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define STORASCAN_HEX_MAX 129
#define STORASCAN_MAX_SWEEP 16        /* cells per block/parallel list           */
#define STORASCAN_LAT_CAP (5u << 20)  /* per-worker latency-sample ceiling        */
#define STORASCAN_MSG (XRDC_MSG_MAX + 32) /* room for a short prefix + st.msg     */

/* exit codes (verify mirrors xrdckverify) */
#define SX_OK        0
#define SX_MISMATCH  1
#define SX_NORECORD  2
#define SX_ERROR     3
#define SX_USAGE     64

/*
 * usage_fp — print xrdstorascan usage to the given stream.
 * WHY: --help (WS-2) must go to stdout; no-arg / unknown-mode goes to stderr.
 *      Returns rc so callers can write `return usage_fp(stderr, SX_USAGE)`.
 */
static int
usage_fp(FILE *out, int rc)
{
    fprintf(out,
        "usage: xrdstorascan <mode> <url> [options]\n"
        "\n"
        "  verify <url> [--algo NAME] [-q]\n"
        "      End-to-end verify ONE file: download it, recompute the checksum,\n"
        "      compare to the server's recorded value. (--algo default adler32)\n"
        "      exit: 0 match, 1 mismatch, 2 no recorded checksum, 3 error\n"
        "\n"
        "  bench <url> [--op read] [--block SZ[,SZ...]] [--parallel N[,N...]]\n"
        "              [--duration S | --count N] [--pattern seq|random] [--json]\n"
        "      Throughput/latency sweep against the gateway. SZ accepts K/M/G.\n"
        "      defaults: --block 1M,4M --parallel 1,8 --duration 5 --pattern seq\n"
        "\n"
        "  dump|verify|fill|compare <dashboard-url> [--path P] [--algo A]\n"
        "              [--password PW] [--insecure] [--json|--summary]\n"
        "      Server-side scan over the /brix/api/v1/scan admin endpoint:\n"
        "      dump/backfill/verify checksums-at-rest across a subtree. URL is the\n"
        "      http(s):// dashboard base; auth via --password or $XRDSTORASCAN_PASSWORD.\n"
        "      verify/compare exit 1 when a mismatch (bit-rot) is found.\n"
        "\n"
        "  (inspect / inventory / drift / health require later server phases.)\n"
        BRIX_USAGE_FOOTER("xrdstorascan"));
    return rc;
}

static int
usage(int rc)
{
    return usage_fp(stderr, rc);
}

/* ---- shared ---------------------------------------------------------------- */

/*
 * opt_take — match argv[*i] against a value-taking option and consume it.
 * WHY: every subcommand's arg loop repeats the same "flag + next-arg" pattern;
 *      one matcher keeps each parse loop under the complexity gate.
 * HOW: exact-match the flag name AND require a following value; on match the
 *      value is stored in *out and *i is advanced past it. A flag without a
 *      value returns 0, so callers fall through to their unknown-option path
 *      (usage/SX_USAGE) exactly as before.
 */
static int
opt_take(const char *name, int argc, char **argv, int *i, const char **out)
{
    if (strcmp(argv[*i], name) != 0 || *i + 1 >= argc) {
        return 0;
    }
    *i += 1;
    *out = argv[*i];
    return 1;
}

/* Parse + connect to the endpoint in `url`. 0 on success (c/u filled), else a
 * shell exit code already reported to stderr. */
static int
storascan_connect(const char *url, brix_url *u, brix_conn *c, brix_status *st)
{
    brix_status_clear(st);
    if (brix_endpoint_parse(url, u, st) != 0) {
        fprintf(stderr, "xrdstorascan: %s\n", st->msg);
        return SX_USAGE;
    }
    if (u->path[0] == '\0' || strcmp(u->path, "/") == 0) {
        fprintf(stderr, "xrdstorascan: a file path is required in the URL\n");
        return SX_USAGE;
    }
    if (brix_connect(c, u, NULL, st) != 0) {
        fprintf(stderr, "xrdstorascan: connect %s:%d: %s\n",
                u->host, u->port, st->msg);
        return brix_shellcode(st);
    }
    return SX_OK;
}

/* ---- verify (A1) ---------------------------------------------------------- */

/* Stream the whole remote file into a private anonymous temp fd. Returns the fd
 * (already unlinked, caller closes) or -1 with *st set. */
static int
verify_download_tmp(brix_conn *c, const char *path, brix_status *st)
{
    char     tmpl[] = "/tmp/xrdstorascan.XXXXXX";
    int      fd;
    brix_file f;
    int64_t  off = 0;
    char    *buf;

    fd = mkstemp(tmpl);
    if (fd < 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "mkstemp failed");
        return -1;
    }
    (void) unlink(tmpl);    /* anonymous fd — no symlink/planted-file race */

    if (brix_file_open_read(c, path, &f, st) != 0) {
        close(fd);
        return -1;
    }
    buf = (char *) malloc(1u << 20);
    if (buf == NULL) {
        brix_file_close(c, &f, st);
        close(fd);
        brix_status_set(st, XRDC_ESOCK, 0, "out of memory");
        return -1;
    }
    for (;;) {
        ssize_t n = brix_file_read(c, &f, off, buf, 1u << 20, st);
        if (n < 0) {
            free(buf);
            brix_file_close(c, &f, st);
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        if (write(fd, buf, (size_t) n) != n) {
            free(buf);
            brix_file_close(c, &f, st);
            close(fd);
            brix_status_set(st, XRDC_ESOCK, 0, "temp write failed");
            return -1;
        }
        off += n;
    }
    free(buf);
    (void) brix_file_close(c, &f, st);
    return fd;
}

/*
 * verify_help — print the verify subcommand usage to stdout (WS-2).
 * WHY: --help as the first subcommand arg must exit cleanly to stdout;
 *      avoids falling through to the unknown-option path (exit 64, stderr).
 * HOW: one printf of the frozen usage text; returns SX_OK for the caller.
 */
static int
verify_help(void)
{
    printf("usage: xrdstorascan verify <url> [--algo NAME] [-q]\n"
           "    End-to-end verify ONE file: download it, recompute the\n"
           "    checksum, compare to the server's recorded value.\n"
           "    (--algo default adler32)\n"
           "    exit: 0 match, 1 mismatch, 2 no recorded checksum, 3 error\n"
           BRIX_USAGE_FOOTER("xrdstorascan"));
    return SX_OK;
}

/*
 * verify_parse_args — decode `verify` options into url/algo/quiet.
 * WHY: keeps cmd_verify a linear pipeline (parse → connect → compare).
 * HOW: --algo takes a value, -q/--quiet sets quiet, exactly one positional
 *      URL; anything else (or a missing URL) prints usage → SX_USAGE.
 */
static int
verify_parse_args(int argc, char **argv, const char **url,
                  const char **algo, int *quiet)
{
    int i;

    for (i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (opt_take("--algo", argc, argv, &i, algo)) {
            continue;
        }
        if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            *quiet = 1;
        } else if (a[0] == '-') {
            return usage(SX_USAGE);
        } else if (*url == NULL) {
            *url = a;
        } else {
            return usage(SX_USAGE);
        }
    }
    if (*url == NULL) {
        return usage(SX_USAGE);
    }
    return SX_OK;
}

/*
 * verify_compute_wire_hex — recompute the checksum from bytes over the wire.
 * WHY: the download+rewind+digest block is a self-contained step of the
 *      verify pipeline; isolating it keeps cmd_verify under the gate.
 * HOW: stream the file into an anonymous temp fd, rewind, digest it with the
 *      requested algorithm; errors are reported to stderr here and mapped to
 *      the shell exit code the caller returns (caller still owns brix_close).
 */
static int
verify_compute_wire_hex(brix_conn *c, const char *path,
                        brix_cksum_algo algo, char *hex, size_t hexsz)
{
    brix_status st;
    int         tmpfd;

    brix_status_clear(&st);
    tmpfd = verify_download_tmp(c, path, &st);
    if (tmpfd < 0) {
        fprintf(stderr, "xrdstorascan: download %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    if (lseek(tmpfd, 0, SEEK_SET) < 0 ||
        brix_cksum_fd(tmpfd, algo, hex, hexsz, &st) != 0) {
        fprintf(stderr, "xrdstorascan: checksum %s: %s\n", path, st.msg);
        close(tmpfd);
        return SX_ERROR;
    }
    close(tmpfd);
    return SX_OK;
}

static int
cmd_verify(int argc, char **argv)
{
    const char     *url = NULL;
    const char     *algo = "adler32";
    int             quiet = 0;
    brix_url        u;
    brix_conn       c;
    brix_status     st;
    brix_cksum_algo algo_enum;
    char            server_hex[STORASCAN_HEX_MAX];
    char            computed_hex[STORASCAN_HEX_MAX];
    int             rc;
    storascan_cks_status verdict;

    if (argc >= 1 && strcmp(argv[0], "--help") == 0) {
        return verify_help();
    }
    rc = verify_parse_args(argc, argv, &url, &algo, &quiet);
    if (rc != SX_OK) {
        return rc;
    }
    if (brix_cksum_algo_parse(algo, &algo_enum) != 0) {
        fprintf(stderr, "xrdstorascan: unsupported algorithm '%s'\n", algo);
        return SX_USAGE;
    }

    rc = storascan_connect(url, &u, &c, &st);
    if (rc != SX_OK) {
        return rc;
    }

    /* Reference value: the server's recorded checksum. */
    if (brix_query_cksum(&c, u.path, algo, server_hex, sizeof(server_hex), &st) != 0) {
        fprintf(stderr, "xrdstorascan: %s %s: %s\n", "query checksum", u.path, st.msg);
        brix_close(&c);
        return brix_shellcode(&st);
    }

    /* Recompute from the bytes pulled over the wire. */
    rc = verify_compute_wire_hex(&c, u.path, algo_enum,
                                 computed_hex, sizeof(computed_hex));
    brix_close(&c);
    if (rc != SX_OK) {
        return rc;
    }

    verdict = storascan_cks_compare(computed_hex, server_hex);
    switch (verdict) {
    case STORASCAN_CKS_MATCH:
        if (!quiet) {
            printf("OK %s %s %s\n", u.path, algo, computed_hex);
        }
        return SX_OK;
    case STORASCAN_CKS_MISMATCH:
        fprintf(stderr, "MISMATCH %s %s: wire=%s recorded=%s\n",
                u.path, algo, computed_hex, server_hex);
        return SX_MISMATCH;
    case STORASCAN_CKS_MISSING:
    default:
        fprintf(stderr, "NO-RECORD %s %s: server reported no checksum\n",
                u.path, algo);
        return SX_NORECORD;
    }
}

/* ---- bench (B1) ----------------------------------------------------------- */

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
bench_help(void)
{
    printf("usage: xrdstorascan bench <url> [--op read]\n"
           "                         [--block SZ[,SZ...]] [--parallel N[,N...]]\n"
           "                         [--duration S | --count N]\n"
           "                         [--pattern seq|random] [--json]\n"
           "    Throughput/latency sweep against the gateway. SZ accepts K/M/G.\n"
           "    defaults: --block 1M,4M --parallel 1,8 --duration 5 --pattern seq\n"
           BRIX_USAGE_FOOTER("xrdstorascan"));
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
bench_parse_args(int argc, char **argv, bench_args_t *ba)
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
            return usage(SX_USAGE);
        } else if (ba->url == NULL) {
            ba->url = a;
        } else {
            return usage(SX_USAGE);
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
bench_validate_args(bench_args_t *ba)
{
    if (ba->url == NULL) {
        return usage(SX_USAGE);
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

static int
cmd_bench(int argc, char **argv)
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
        return bench_help();
    }

    memset(&ba, 0, sizeof(ba));
    ba.block_s = "1M,4M";
    ba.par_s = "1,8";
    ba.pattern = "seq";
    ba.duration_s = 5;

    rc = bench_parse_args(argc, argv, &ba);
    if (rc != SX_OK) {
        return rc;
    }
    rc = bench_validate_args(&ba);
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

/* ---- engine modes (dump/verify/fill/compare) — HTTP client over /scan ----- */

typedef struct {
    int  tls;
    char host[256];
    int  port;
} scan_ep;

/*
 * scan_args_t — decoded engine-mode (dump/verify/fill/…) command line.
 * WHY: one state block for parse → fetch → render instead of seven loose
 *      locals, and it carries the auth pair (password/insecure) that
 *      scan_login needs without pushing its signature over the arg gate.
 */
typedef struct {
    const char *url;          /* http(s):// dashboard base                  */
    const char *path;         /* --path subtree (default "/")               */
    const char *alg;          /* --algo checksum name (default adler32)     */
    const char *password;     /* --password / $XRDSTORASCAN_PASSWORD        */
    int         insecure;     /* --insecure: skip TLS peer verification     */
    int         as_json;      /* --json: raw NDJSON passthrough             */
    int         summary_only; /* --summary: print only the summary line     */
} scan_args_t;

/* Parse http(s)://host[:port][/...] — only scheme/host/port are used. */
static int
scan_parse_url(const char *url, scan_ep *ep)
{
    const char *p, *slash, *colon;
    size_t      hlen;

    if (strncmp(url, "https://", 8) == 0) {
        ep->tls = 1; p = url + 8; ep->port = 443;
    } else if (strncmp(url, "http://", 7) == 0) {
        ep->tls = 0; p = url + 7; ep->port = 80;
    } else {
        return -1;
    }
    slash = strchr(p, '/');
    colon = strchr(p, ':');
    if (colon != NULL && (slash == NULL || colon < slash)) {
        hlen = (size_t) (colon - p);
        ep->port = atoi(colon + 1);
    } else {
        hlen = slash ? (size_t) (slash - p) : strlen(p);
    }
    if (hlen == 0 || hlen >= sizeof(ep->host) || ep->port <= 0) {
        return -1;
    }
    memcpy(ep->host, p, hlen);
    ep->host[hlen] = '\0';
    return 0;
}

/* POST /brix/login (password) → capture the session cookie. 0 / -1. */
static int
scan_login(const scan_ep *ep, const scan_args_t *sa,
           char *cookie, size_t cksz, brix_status *st)
{
    brix_http_resp resp;
    char           body[256];
    char           sc[512];
    int            n, ok;

    n = snprintf(body, sizeof(body), "password=%s", sa->password);
    if (brix_http_req(ep->host, ep->port, ep->tls, "POST", "/brix/login",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      body, (size_t) n, 15000, sa->insecure ? 0 : 1, NULL,
                      &resp, st) != 0)
    {
        return -1;
    }
    cookie[0] = '\0';
    if (brix_http_header(&resp, "Set-Cookie", sc, sizeof(sc))) {
        char *semi = strchr(sc, ';');
        if (semi != NULL) {
            *semi = '\0';
        }
        snprintf(cookie, cksz, "%s", sc);
    }
    ok = (resp.status == 200 || resp.status == 302) && cookie[0] != '\0';
    brix_http_resp_free(&resp);
    if (!ok) {
        brix_status_set(st, XRDC_EAUTH, 0, "dashboard login failed (bad password?)");
        return -1;
    }
    return 0;
}

/* Minimal JSON field extractor over one controlled NDJSON line: copies the value
 * of "key" into out[outsz]. Strings are returned without surrounding quotes (no
 * unescaping — values here are paths/hex/short tokens). 1 found, 0 absent. */
static int
scan_json_field(const char *line, const char *key, char *out, size_t outsz)
{
    char   pat[48];
    const char *p;
    size_t o = 0;

    snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(line, pat);
    if (p == NULL) {
        return 0;
    }
    p += strlen(pat);
    if (*p == '"') {
        p++;
        while (*p != '\0' && *p != '"' && o + 1 < outsz) {
            if (*p == '\\' && p[1] != '\0') {
                p++;   /* keep the escaped char verbatim */
            }
            out[o++] = *p++;
        }
    } else {
        while (*p != '\0' && *p != ',' && *p != '}' && o + 1 < outsz) {
            out[o++] = *p++;
        }
    }
    out[o] = '\0';
    return 1;
}

/*
 * scan_render_summary — print the summary record; return its mismatch count.
 * WHY: the summary line both renders AND yields the verify/compare exit
 *      signal, so it is the one record type with a return value.
 * HOW: raw passthrough in --json/--summary mode, otherwise the frozen
 *      "# files=… ok=…" counter line.
 */
static long
scan_render_summary(const char *buf, int as_json, int summary_only)
{
    char mm[24] = "0";

    scan_json_field(buf, "mismatch", mm, sizeof(mm));
    if (as_json || summary_only) {
        printf("%s\n", buf);
    } else {
        char files[24] = "0", ok[24] = "0", miss[24] = "0",
             un[24] = "0";
        scan_json_field(buf, "files", files, sizeof(files));
        scan_json_field(buf, "ok", ok, sizeof(ok));
        scan_json_field(buf, "missing", miss, sizeof(miss));
        scan_json_field(buf, "unreadable", un, sizeof(un));
        printf("# files=%s ok=%s mismatch=%s missing=%s unreadable=%s\n",
               files, ok, mm, miss, un);
    }
    return atol(mm);
}

/*
 * scan_render_inspect — TSV line for one "inspect" record.
 * WHY/HOW: pulls the frozen field set out of the NDJSON line and prints the
 *      frozen backend/size/path row.
 */
static void
scan_render_inspect(const char *buf)
{
    char path[1024] = "", backend[24] = "-", src[24] = "-",
         size[24] = "0", cons[8] = "-";

    scan_json_field(buf, "path", path, sizeof(path));
    scan_json_field(buf, "backend", backend, sizeof(backend));
    scan_json_field(buf, "stored_src", src, sizeof(src));
    scan_json_field(buf, "size", size, sizeof(size));
    scan_json_field(buf, "namespace_consistent", cons, sizeof(cons));
    printf("%-8s %-12s %s\tstored_src=%s consistent=%s\n",
           backend, size, path, src, cons);
}

/*
 * scan_render_health — TSV line for one "health" record.
 * WHY/HOW: frozen backend capacity line (total/used/free bytes).
 */
static void
scan_render_health(const char *buf)
{
    char backend[24] = "-", total[24] = "0", freeb[24] = "0",
         used[24] = "0";

    scan_json_field(buf, "backend", backend, sizeof(backend));
    scan_json_field(buf, "total_bytes", total, sizeof(total));
    scan_json_field(buf, "free_bytes", freeb, sizeof(freeb));
    scan_json_field(buf, "used_bytes", used, sizeof(used));
    printf("backend=%s total=%s used=%s free=%s\n",
           backend, total, used, freeb);
}

/*
 * scan_render_object — TSV line for one "object" (inventory) record.
 * WHY/HOW: frozen size/path/key row; a pathless object prints "(orphan)".
 */
static void
scan_render_object(const char *buf)
{
    char key[1024] = "", path[1024] = "", size[24] = "0",
         orphan[8] = "-";

    scan_json_field(buf, "key", key, sizeof(key));
    scan_json_field(buf, "path", path, sizeof(path));
    scan_json_field(buf, "size", size, sizeof(size));
    scan_json_field(buf, "orphan", orphan, sizeof(orphan));
    printf("%-12s %s\tkey=%s orphan=%s\n",
           size, path[0] ? path : "(orphan)", key, orphan);
}

/*
 * scan_render_drift — TSV line for one "drift" record.
 * WHY/HOW: frozen class/size/key/path row.
 */
static void
scan_render_drift(const char *buf)
{
    char cls[24] = "-", key[1024] = "", path[1024] = "",
         size[24] = "0";

    scan_json_field(buf, "class", cls, sizeof(cls));
    scan_json_field(buf, "key", key, sizeof(key));
    scan_json_field(buf, "path", path, sizeof(path));
    scan_json_field(buf, "size", size, sizeof(size));
    printf("%-14s %-12s key=%s path=%s\n", cls, size, key, path);
}

/*
 * scan_render_file — TSV line for one "file" (checksum) record.
 * WHY/HOW: frozen status/size/path row with stored vs computed hex.
 */
static void
scan_render_file(const char *buf)
{
    char path[1024] = "", status[24] = "-", stored[136] = "-",
         computed[136] = "-", size[24] = "0";

    scan_json_field(buf, "path", path, sizeof(path));
    scan_json_field(buf, "status", status, sizeof(status));
    scan_json_field(buf, "size", size, sizeof(size));
    scan_json_field(buf, "stored", stored, sizeof(stored));
    scan_json_field(buf, "computed", computed, sizeof(computed));
    printf("%-10s %-12s %s\tstored=%s computed=%s\n",
           status, size, path, stored, computed);
}

/*
 * scan_render_row — route one non-summary NDJSON record to its printer.
 * WHY: keeps the per-record formatting knowledge out of the body walker.
 * HOW: raw passthrough in --json mode, nothing in --summary mode, otherwise
 *      dispatch on the record's "t" tag ("file" is the default shape).
 */
static void
scan_render_row(const char *buf, const char *t, int as_json, int summary_only)
{
    if (as_json) {
        if (!summary_only) {
            printf("%s\n", buf);
        }
    } else if (summary_only) {
        /* nothing: only the summary line is printed in summary mode */
    } else if (strcmp(t, "inspect") == 0) {
        scan_render_inspect(buf);
    } else if (strcmp(t, "health") == 0) {
        scan_render_health(buf);
    } else if (strcmp(t, "object") == 0) {
        scan_render_object(buf);
    } else if (strcmp(t, "drift") == 0) {
        scan_render_drift(buf);
    } else {   /* "file" */
        scan_render_file(buf);
    }
}

/* Render the NDJSON body: TSV (default), raw json, or summary-only. Returns the
 * mismatch count seen in the summary (for the verify/compare exit code). */
static long
scan_render(const char *body, int as_json, int summary_only)
{
    const char *line = body;
    long        mismatch = 0;

    while (line != NULL && *line != '\0') {
        const char *nl = strchr(line, '\n');
        size_t      len = nl ? (size_t) (nl - line) : strlen(line);
        char        buf[4096];
        char        t[16];

        if (len >= sizeof(buf)) {
            len = sizeof(buf) - 1;
        }
        memcpy(buf, line, len);
        buf[len] = '\0';

        if (scan_json_field(buf, "t", t, sizeof(t))) {
            if (strcmp(t, "summary") == 0) {
                mismatch = scan_render_summary(buf, as_json, summary_only);
            } else {
                scan_render_row(buf, t, as_json, summary_only);
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return mismatch;
}

/* URL-encode a query value (conservative: keep unreserved + '/'). */
static void
scan_qencode(const char *in, char *out, size_t outsz)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;

    for (; *in != '\0' && o + 4 < outsz; in++) {
        unsigned char c = (unsigned char) *in;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '/' || c == '.' || c == '-'
            || c == '_' || c == '~')
        {
            out[o++] = (char) c;
        } else {
            out[o++] = '%';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 0xf];
        }
    }
    out[o] = '\0';
}

/* Parse cmd_scan's flag ladder into `sa`. WHAT: --path/--algo/--password/
 * --insecure/--json/--summary plus the single positional dashboard URL.
 * WHY: cmd_scan's parse half is independent of the fetch/render halves; the
 *      decoded scan_args_t is what scan_login and the fetch consume.
 * HOW: same first-match ladder as before; unknown dash-word or a second
 *      positional → -1 (caller emits usage). */
static int
scan_parse_scan_args(int argc, char **argv, scan_args_t *sa)
{
    int i;

    for (i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--path") == 0 && i + 1 < argc) {
            sa->path = argv[++i];
        } else if (strcmp(a, "--algo") == 0 && i + 1 < argc) {
            sa->alg = argv[++i];
        } else if (strcmp(a, "--password") == 0 && i + 1 < argc) {
            sa->password = argv[++i];
        } else if (strcmp(a, "--insecure") == 0) {
            sa->insecure = 1;
        } else if (strcmp(a, "--json") == 0) {
            sa->as_json = 1;
        } else if (strcmp(a, "--summary") == 0) {
            sa->summary_only = 1;
        } else if (a[0] == '-') {
            return -1;
        } else if (sa->url == NULL) {
            sa->url = a;
        } else {
            return -1;
        }
    }
    return 0;
}

/* Run the authenticated GET against /brix/api/v1/scan. WHAT: builds the
 * mode/path/alg query + Cookie header and fetches into *resp.
 * WHY: the network half of cmd_scan, split from parse and render.
 * HOW: query-encodes path/alg, formats the request, maps transport failure
 *      to the shell code and a non-200 to SX_ERROR with the same hints. */
static int
scan_fetch(const char *mode, const scan_ep *ep, const scan_args_t *sa,
           const char *cookie, brix_http_resp *resp)
{
    char        epath[2048], ealg[64], query[2240], hdr[640];
    char        fullpath[2304];
    brix_status st;

    brix_status_clear(&st);
    scan_qencode(sa->path, epath, sizeof(epath));
    scan_qencode(sa->alg, ealg, sizeof(ealg));
    snprintf(query, sizeof(query), "mode=%s&path=%s&alg=%s", mode, epath, ealg);
    snprintf(hdr, sizeof(hdr), "Cookie: %s\r\n", cookie);

    snprintf(fullpath, sizeof(fullpath), "/brix/api/v1/scan?%s", query);
    if (brix_http_req(ep->host, ep->port, ep->tls, "GET", fullpath, hdr,
                      NULL, 0, 120000, sa->insecure ? 0 : 1, NULL, resp, &st) != 0)
    {
        fprintf(stderr, "xrdstorascan: %s: %s\n", mode, st.msg);
        return brix_shellcode(&st);
    }
    if (resp->status != 200) {
        fprintf(stderr, "xrdstorascan: %s: server returned HTTP %d%s\n",
                mode, resp->status,
                resp->status == 404 ? " (scan disabled? — set brix_scan_root)"
                : resp->status == 401 ? " (auth — check password)" : "");
        brix_http_resp_free(resp);
        return SX_ERROR;
    }
    return SX_OK;
}

static int
cmd_scan(const char *mode, int argc, char **argv)
{
    scan_args_t    sa = { NULL, "/", "adler32", NULL, 0, 0, 0 };
    scan_ep        ep;
    char           cookie[512] = "";
    brix_http_resp resp;
    brix_status    st;
    long           mismatch;
    int            rc;

    sa.password = getenv("XRDSTORASCAN_PASSWORD");

    /* --help as the first subcommand arg → print this mode's usage to stdout
     * and exit cleanly (WS-2). */
    if (argc >= 1 && strcmp(argv[0], "--help") == 0) {
        printf("usage: xrdstorascan %s <dashboard-url> [--path P] [--algo A]\n"
               "                    [--password PW] [--insecure] [--json|--summary]\n"
               "    Server-side scan over the /brix/api/v1/scan admin endpoint.\n"
               "    auth via --password or $XRDSTORASCAN_PASSWORD\n"
               BRIX_USAGE_FOOTER("xrdstorascan"),
               mode);
        return SX_OK;
    }

    if (scan_parse_scan_args(argc, argv, &sa) != 0 || sa.url == NULL) {
        return usage(SX_USAGE);
    }
    if (scan_parse_url(sa.url, &ep) != 0) {
        fprintf(stderr, "xrdstorascan: %s needs an http(s):// dashboard URL\n", mode);
        return SX_USAGE;
    }
    if (sa.password == NULL) {
        fprintf(stderr, "xrdstorascan: %s needs --password or $XRDSTORASCAN_PASSWORD\n",
                mode);
        return SX_USAGE;
    }

    brix_status_clear(&st);
    if (scan_login(&ep, &sa, cookie, sizeof(cookie), &st) != 0) {
        fprintf(stderr, "xrdstorascan: %s\n", st.msg);
        return brix_shellcode(&st);
    }

    rc = scan_fetch(mode, &ep, &sa, cookie, &resp);
    if (rc != SX_OK) {
        return rc;
    }

    mismatch = scan_render(resp.body ? resp.body : "", sa.as_json,
                           sa.summary_only);
    brix_http_resp_free(&resp);

    /* verify/compare: corruption found ⇒ non-zero for scripting */
    if ((strcmp(mode, "verify") == 0 || strcmp(mode, "compare") == 0)
        && mismatch > 0)
    {
        return SX_MISMATCH;
    }
    return SX_OK;
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        return usage(SX_USAGE);
    }
    /* `verify` routes by URL scheme: an http(s):// dashboard URL → the
     * server-engine verify; a root:// URL → the client-side end-to-end check. */
    if (strcmp(argv[1], "verify") == 0) {
        if (argc >= 3 && (strncmp(argv[2], "http://", 7) == 0
                          || strncmp(argv[2], "https://", 8) == 0))
        {
            return cmd_scan("verify", argc - 2, argv + 2);
        }
        return cmd_verify(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "bench") == 0) {
        return cmd_bench(argc - 2, argv + 2);
    }
    {
        /* Server-engine scan modes routed straight to cmd_scan. */
        static const char *const scan_modes[] = {
            "dump", "fill", "compare", "inspect", "health", "inventory",
            "drift", NULL
        };
        int m;

        for (m = 0; scan_modes[m] != NULL; m++) {
            if (strcmp(argv[1], scan_modes[m]) == 0) {
                return cmd_scan(argv[1], argc - 2, argv + 2);
            }
        }
    }
    if (strcmp(argv[1], "--version") == 0) {
        printf("xrdstorascan (BriX-Cache client) %s\n", brix_client_version());
        return SX_OK;
    }
    if (strcmp(argv[1], "--help") == 0) {
        return usage_fp(stdout, SX_OK);    /* --help → stdout (WS-2) */
    }
    if (strcmp(argv[1], "-h") == 0) {
        return usage(SX_OK);               /* -h → stderr (C1) */
    }
    fprintf(stderr, "xrdstorascan: unknown mode '%s'\n", argv[1]);
    return usage(SX_USAGE);
}
