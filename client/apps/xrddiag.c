/*
 * xrddiag.c — consolidated deployment-diagnostic CLI for an XRootD endpoint.
 *
 * WHAT: `xrddiag <check|bench|topology|status|compare> [opts] <url> [...]` — a
 *       single tool that answers "is this server behaving correctly, how fast is
 *       it, what does the cluster look like, and does it match a reference?".
 * WHY:  Operators (and the test harness) want one binary that exercises the same
 *       libxrdc paths a real client uses and reports pass/fail + numbers, instead
 *       of a pile of ad-hoc xrdfs/xrdcp invocations. Every subcommand is a thin
 *       composition of existing libxrdc calls — no new wire code.
 * HOW:  Parse common connection opts (the xrdcp/xrdfs grammar) + a subcommand,
 *       connect once with xrdc_connect, then:
 *         check    — green/red protocol-correctness probes (exit nonzero on FAIL)
 *         bench    — timed download (single vs --streams N), report MB/s
 *         topology — xrdc_locate + redirect-loop convergence (+ optional /cluster)
 *         status   — pull /metrics (xrdc_http_get) and summarise it
 *         compare  — stat size + dirlist set + md5 vs a --vs-reference endpoint
 *
 * Clean-room: composes the public libxrdc API only; no XrdCl, no libcurl.
 */
#include "xrdc.h"
#include "compat/crypto.h"   /* xrootd_crypto_init + HMAC-SHA256/SHA-256 (S3 SigV4) */
#include "compat/hex.h"      /* xrootd_hex_encode (lowercase, for SigV4) */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>     /* watch: cooperative SIGINT/SIGTERM stop */
#include <stdarg.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Shared parsed arguments for every subcommand. */
typedef struct {
    xrdc_opts   conn;          /* connection opts (TLS/auth/trace/timing) */
    const char *url;           /* primary endpoint/url (positional 0) */
    const char *ref_url;       /* compare: --vs-reference endpoint */
    int         streams;       /* bench: -S/--streams N (0 = single) */
    int         metrics_port;  /* status: /metrics port (default 9100) */
    const char *cluster_url;   /* topology: optional cleartext /cluster JSON URL */
    int         authorized;    /* probe-robustness: --i-am-authorized */
    int         probe_timeout_ms; /* probe-robustness: per-probe deadline */
    const char *playback_url;  /* replay: re-issue captured requests against URL */
    const char *davs;          /* compare: cleartext WebDAV endpoint (host[:port]) */
    int         sweep;         /* bench: --sweep read-size knee table */
    int         json;          /* remote-doctor: emit JSON instead of human report */
    int         dashboard_port;/* remote-doctor: dashboard JSON port (0 = skip) */
    int         allow_write;   /* remote-doctor: enable mutating write/stage probes */
    int         auth_suite;    /* remote-doctor: run the full auth/permissions suite */
    int         verify_tls;    /* remote-doctor: verify HTTPS/davs/s3 peer cert (default 1) */
    const char *urls[8];       /* remote-doctor: the N endpoint URLs (a transfer path) */
    int         nurls;
    int         interval_s;    /* watch: seconds between cycles (default 10) */
    int         count;         /* watch: number of cycles (0 = forever) */
    int         watch_prom;    /* watch: emit Prometheus exposition */
    const char *prom_path;     /* watch: --prometheus=PATH (NULL = stdout) */
} diag_args;

/* ------------------------------------------------------------------ */
/* probe bookkeeping (check)                                           */
/* ------------------------------------------------------------------ */

static int g_fails;

static void
probe(const char *name, int ok, const char *fmt, ...)
{
    char    detail[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);

    if (!ok) {
        g_fails++;
    }
    printf("  [%s] %-22s %s\n", ok ? "PASS" : "FAIL", name, detail);
}

static void
note(const char *name, const char *fmt, ...)
{
    char    detail[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    printf("  [NOTE] %-22s %s\n", name, detail);
}

/* ------------------------------------------------------------------ */
/* shared helpers                                                      */
/* ------------------------------------------------------------------ */

/* Stream a remote file through the live connection into fd; returns 0 / -1 and
 * sets *out_bytes to the number of bytes written. Reuses the authenticated conn
 * (no reconnect), so it measures the data path itself. */
static int
download_to_fd(xrdc_conn *c, const char *path, int fd, int64_t *out_bytes,
               xrdc_status *st)
{
    xrdc_file f;
    int64_t   off = 0;
    char     *buf;

    if (xrdc_file_open_read(c, path, &f, st) != 0) {
        return -1;
    }
    buf = (char *) malloc(1u << 20);
    if (buf == NULL) {
        xrdc_file_close(c, &f, st);
        xrdc_status_set(st, XRDC_EPROTO, 0, "download: out of memory");
        return -1;
    }
    for (;;) {
        ssize_t r = xrdc_file_read(c, &f, off, buf, 1u << 20, st);
        ssize_t w = 0;
        if (r < 0) {
            free(buf);
            xrdc_file_close(c, &f, st);
            return -1;
        }
        if (r == 0) {
            break;
        }
        while (w < r) {
            ssize_t k = write(fd, buf + w, (size_t) (r - w));
            if (k < 0) {
                free(buf);
                xrdc_file_close(c, &f, st);
                xrdc_status_set(st, XRDC_ESOCK, 0, "download: local write failed");
                return -1;
            }
            w += k;
        }
        off += r;
    }
    free(buf);
    if (out_bytes != NULL) {
        *out_bytes = off;
    }
    return xrdc_file_close(c, &f, st);
}

/* Choose a remote regular file to operate on: if the URL carried an explicit
 * path (not "/") use it; otherwise list "/" and pick the largest regular file.
 * Fills target[tsz] with the absolute path and *sti with its stat. 0 / -1. */
static int
resolve_target(xrdc_conn *c, const xrdc_url *u, char *target, size_t tsz,
               xrdc_statinfo *sti, xrdc_status *st)
{
    xrdc_dirent *ents = NULL;
    size_t       n = 0, i;
    int64_t      best = -1;
    int          found = 0;

    if (u->path[0] != '\0' && strcmp(u->path, "/") != 0) {
        if (xrdc_stat(c, u->path, sti, st) != 0) {
            return -1;
        }
        if (sti->flags & kXR_isDir) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "%s is a directory", u->path);
            return -1;
        }
        snprintf(target, tsz, "%s", u->path);
        return 0;
    }

    if (xrdc_dirlist(c, "/", 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (!ents[i].have_stat || (ents[i].st.flags & kXR_isDir)) {
            continue;
        }
        if (ents[i].st.size > best) {
            best = ents[i].st.size;
            snprintf(target, tsz, "/%s", ents[i].name);
            *sti = ents[i].st;
            found = 1;
        }
    }
    free(ents);
    if (!found) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "no regular file under / to test (pass a file URL)");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* check — protocol-correctness probes                                 */
/* ------------------------------------------------------------------ */

static int
do_check(const diag_args *a)
{
    xrdc_url      u;
    xrdc_conn     c;
    xrdc_status   st;
    xrdc_statinfo sti;
    char          target[XRDC_PATH_MAX];
    int           have_file;

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (xrdc_connect(&c, &u, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }

    printf("Session facts:\n");
    xrdc_explain_conn(&c, &a->conn, stdout);
    printf("Probes:\n");

    /* (1) auth-as-advertised: the driver's chosen protocol must be anon (no &P=)
     *     or appear in the server's advertised security list. */
    if (c.sec_list[0] == '\0') {
        probe("auth-as-advertised", c.diag.chosen_auth == NULL,
              c.diag.chosen_auth == NULL ? "anonymous (no &P= offered)"
                                         : "client used %s but server offered none",
              c.diag.chosen_auth ? c.diag.chosen_auth : "");
    } else {
        int ok = (c.diag.chosen_auth != NULL) &&
                 (strstr(c.sec_list, c.diag.chosen_auth) != NULL);
        probe("auth-as-advertised", ok, "chose %s from \"%s\"",
              c.diag.chosen_auth ? c.diag.chosen_auth : "(none)", c.sec_list);
    }

    /* (2) no-silent-TLS-downgrade: gotoTLS advertised ⇒ session must be TLS. */
    {
        unsigned f = (unsigned) c.server_flags;
        const char *v = NULL, *cf = NULL;
        int tls_active = xrdc_tls_info(&c, &v, &cf);
        if (f & kXR_gotoTLS) {
            probe("no-tls-downgrade", tls_active,
                  tls_active ? "gotoTLS honored (%s)" : "gotoTLS advertised but cleartext!",
                  v ? v : "");
        } else {
            note("no-tls-downgrade", tls_active ? "TLS active" : "cleartext (gotoTLS not required)");
        }
    }

    /* (3) path-confinement: an escape attempt must be refused, never served. */
    {
        xrdc_statinfo esc;
        xrdc_status   est;
        int           rc;
        xrdc_status_clear(&est);
        rc = xrdc_stat(&c, "/../../../../../../etc/passwd", &esc, &est);
        probe("path-confinement", rc != 0,
              rc != 0 ? "escape refused (%s)" : "ESCAPE SERVED — confinement broken!",
              rc != 0 ? xrdc_kxr_name(est.kxr) : "");
    }

    /* (4) dirlist works + (7) dirlist-dstat == stat for the first entry. */
    {
        xrdc_dirent *ents = NULL;
        size_t       n = 0;
        xrdc_status  dst;
        xrdc_status_clear(&dst);
        if (xrdc_dirlist(&c, "/", 1, &ents, &n, &dst) != 0) {
            probe("dirlist", 0, "%s", dst.msg);
        } else {
            probe("dirlist", 1, "%zu entries under /", n);
            /* find a regular file entry with a stat and cross-check it */
            for (size_t i = 0; i < n; i++) {
                if (ents[i].have_stat && !(ents[i].st.flags & kXR_isDir)) {
                    char         p[XRDC_PATH_MAX];
                    xrdc_statinfo s2;
                    xrdc_status   s2st;
                    snprintf(p, sizeof(p), "/%s", ents[i].name);
                    xrdc_status_clear(&s2st);
                    if (xrdc_stat(&c, p, &s2, &s2st) == 0) {
                        probe("dstat==stat", s2.size == ents[i].st.size,
                              "%s size dstat=%lld stat=%lld", ents[i].name,
                              (long long) ents[i].st.size, (long long) s2.size);
                    }
                    break;
                }
            }
            free(ents);
        }
    }

    /* Resolve a file for the integrity probes (skip cleanly if none). */
    have_file = (resolve_target(&c, &u, target, sizeof(target), &sti, &st) == 0);
    if (!have_file) {
        note("checksum/pgread", "skipped — %s", st.msg);
        xrdc_close(&c);
        printf("Result: %d failure(s)\n", g_fails);
        return g_fails ? 1 : 0;
    }

    /* (5) checksum-works: server digest == local digest of the downloaded bytes. */
    {
        char        srv[160], loc[160];
        xrdc_status qst, lst;
        int         tmpfd;
        char        tmpl[] = "/tmp/xrddiag.XXXXXX";

        xrdc_status_clear(&qst);
        if (xrdc_query_cksum(&c, target, "adler32", srv, sizeof(srv), &qst) != 0) {
            note("checksum-works", "server has no adler32 (%s)", qst.msg);
        } else {
            tmpfd = mkstemp(tmpl);
            if (tmpfd < 0) {
                note("checksum-works", "mkstemp failed");
            } else {
                int64_t got = 0;
                xrdc_status_clear(&lst);
                if (download_to_fd(&c, target, tmpfd, &got, &lst) == 0 &&
                    xrdc_cksum_fd(tmpfd, XRDC_CK_ADLER32, loc, sizeof(loc), &lst) == 0) {
                    probe("checksum-works", strcmp(srv, loc) == 0,
                          "%s server=%s local=%s", target, srv, loc);
                } else {
                    probe("checksum-works", 0, "%s", lst.msg);
                }
                close(tmpfd);
                unlink(tmpl);
            }
        }
    }

    /* (6) pgread-integrity: pgread self-validates per-page CRC32c. */
    {
        char        buf[8192];
        xrdc_file   f;
        xrdc_status pst;
        xrdc_status_clear(&pst);
        if (xrdc_file_open_read(&c, target, &f, &pst) != 0) {
            probe("pgread-integrity", 0, "open: %s", pst.msg);
        } else {
            ssize_t r = xrdc_file_pgread(&c, &f, 0, buf, sizeof(buf), &pst);
            probe("pgread-integrity", r >= 0,
                  r >= 0 ? "%zd bytes, all page CRC32c verified" : "%s",
                  r >= 0 ? (size_t) r : 0, r >= 0 ? "" : pst.msg);
            xrdc_file_close(&c, &f, &pst);
        }
    }

    /* (8) POSC-atomicity: a non-finalized POSC upload must leave NO file. Open a
     *     SECOND connection, posc-open + partial write, then ABANDON it (close the
     *     socket without kXR_close) and confirm the path is absent on the main conn. */
    {
        xrdc_conn   pc;
        xrdc_status pst;
        xrdc_file   pf;
        char        ppath[64];
        snprintf(ppath, sizeof(ppath), "/_xrddiag_posc_%d.tmp", (int) getpid());
        xrdc_status_clear(&pst);
        if (xrdc_connect(&pc, &u, &a->conn, &pst) != 0) {
            note("posc-atomicity", "skipped — 2nd connect: %s", pst.msg);
        } else if (xrdc_file_open_write(&pc, ppath, 1, 1, &pf, &pst) != 0) {
            note("posc-atomicity", "skipped — posc open: %s (read-only export?)",
                 pst.msg);
            xrdc_close(&pc);
        } else {
            xrdc_statinfo si;
            xrdc_status   s2;
            int           visible;
            (void) xrdc_file_write(&pc, &pf, 0, "partial", 7, &pst);
            /* ABANDON: drop the socket with no kXR_close → server discards POSC. */
            if (pc.io.fd >= 0) { close(pc.io.fd); pc.io.fd = -1; }
            xrdc_close(&pc);
            xrdc_status_clear(&s2);
            visible = (xrdc_stat(&c, ppath, &si, &s2) == 0);
            probe("posc-atomicity", !visible,
                  visible ? "PARTIAL FILE VISIBLE after abandoned upload!"
                          : "abandoned upload left no file (%s)",
                  visible ? "" : xrdc_kxr_name(s2.kxr));
            if (visible) { xrdc_rm(&c, ppath, &s2); }   /* clean up the leak */
        }
    }

    /* (9) handle-limits: opening files past the server cap must fail GRACEFULLY
     *     (a clean kXR_* error, not a crash/hang) and the connection survive. */
    {
        xrdc_file   fhs[64];
        xrdc_status hst;
        int         opened = 0, i, graceful;
        for (i = 0; i < 64; i++) {
            xrdc_status_clear(&hst);
            if (xrdc_file_open_read(&c, target, &fhs[opened], &hst) != 0) {
                break;
            }
            opened++;
        }
        graceful = (opened < 64);   /* hit a cap with a clean error */
        {
            xrdc_statinfo si;
            xrdc_status   s2;
            int           alive;
            xrdc_status_clear(&s2);
            alive = (xrdc_stat(&c, "/", &si, &s2) == 0) || (s2.kxr > 0);
            if (graceful) {
                probe("handle-limits", alive, "capped at %d open (%s), conn alive",
                      opened, xrdc_kxr_name(hst.kxr));
            } else {
                note("handle-limits", "no cap hit (opened %d), conn %s", opened,
                     alive ? "alive" : "DEAD");
            }
        }
        for (i = 0; i < opened; i++) {
            xrdc_status cs;
            xrdc_status_clear(&cs);
            xrdc_file_close(&c, &fhs[i], &cs);
        }
    }

    /* (10) credential validity / clock-skew: surface env-credential expiry (the
     *      actionable client-side signal — see also `xrdfs explain`). */
    {
        char       *tok = xrdc_token_discover();
        const char *proxy = getenv("X509_USER_PROXY");
        if (tok != NULL || (proxy != NULL && proxy[0] != '\0')) {
            printf("Credential validity:\n");
            if (tok != NULL) { xrdc_token_explain(tok, stdout); free(tok); }
            if (proxy != NULL && proxy[0] != '\0') {
                xrdc_gsi_cert_explain(proxy, stdout);
            }
        } else {
            note("cred-validity", "anonymous — no credential expiry to check");
        }
    }

    xrdc_close(&c);
    printf("Result: %d failure(s)\n", g_fails);
    return g_fails ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* bench — timed download (single vs streams)                          */
/* ------------------------------------------------------------------ */

static double
bench_one(xrdc_conn *c, const char *target, xrdc_status *st)
{
    int      fd;
    char     tmpl[] = "/tmp/xrddiag-bench.XXXXXX";
    int64_t  bytes = 0;
    uint64_t t0, t1;
    double   secs;

    fd = mkstemp(tmpl);
    if (fd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, 0, "mkstemp failed");
        return -1.0;
    }
    t0 = xrdc_mono_ns();
    if (download_to_fd(c, target, fd, &bytes, st) != 0) {
        close(fd);
        unlink(tmpl);
        return -1.0;
    }
    t1 = xrdc_mono_ns();
    close(fd);
    unlink(tmpl);

    secs = (double) (t1 - t0) / 1e9;
    if (secs <= 0.0) {
        secs = 1e-9;
    }
    printf("  %-14s %lld bytes in %.3f s = %.1f MB/s\n",
           "single-stream", (long long) bytes, secs,
           (double) bytes / 1e6 / secs);
    return secs;
}

/* §15.3: sweep read request sizes to expose the throughput knee. Reads the whole
 * file at each size into a discard buffer (no local fd), timing each pass. */
static void
bench_sweep(xrdc_conn *c, const char *target)
{
    static const size_t sizes[] = { 65536, 262144, 1048576, 4194304, 16777216 };
    size_t i;

    printf("Read-size sweep:\n");
    printf("  %-10s %12s\n", "req-size", "MB/s");
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        xrdc_file   f;
        xrdc_status st;
        uint8_t    *buf;
        int64_t     off = 0;
        uint64_t    t0, t1;
        double      secs;

        xrdc_status_clear(&st);
        if (xrdc_file_open_read(c, target, &f, &st) != 0) {
            printf("  %-10zu open: %s\n", sizes[i], st.msg);
            continue;
        }
        buf = (uint8_t *) malloc(sizes[i]);
        if (buf == NULL) {
            xrdc_file_close(c, &f, &st);
            continue;
        }
        t0 = xrdc_mono_ns();
        for (;;) {
            ssize_t r = xrdc_file_read(c, &f, off, buf, sizes[i], &st);
            if (r <= 0) {
                break;
            }
            off += r;
        }
        t1 = xrdc_mono_ns();
        free(buf);
        xrdc_file_close(c, &f, &st);
        secs = (double) (t1 - t0) / 1e9;
        if (secs <= 0.0) {
            secs = 1e-9;
        }
        printf("  %-10zu %12.1f\n", sizes[i], (double) off / 1e6 / secs);
    }
}

static int
do_bench(const diag_args *a)
{
    xrdc_url      u;
    xrdc_conn     c;
    xrdc_status   st;
    xrdc_statinfo sti;
    char          target[XRDC_PATH_MAX];
    char          root_url[XRDC_PATH_MAX + 512];   /* scheme + host + ':' + port + path */

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (xrdc_connect(&c, &u, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }
    if (resolve_target(&c, &u, target, sizeof(target), &sti, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        xrdc_close(&c);
        return xrdc_shellcode(&st);
    }
    printf("Benchmark: %s (%lld bytes)\n", target, (long long) sti.size);
    xrdc_netdiag_report(&c, stdout);   /* §15.3: phases + family + TCP_INFO */

    if (a->sweep) {                    /* §15.3: read-size knee table, then done */
        bench_sweep(&c, target);
        xrdc_close(&c);
        return 0;
    }

    if (bench_one(&c, target, &st) < 0.0) {
        fprintf(stderr, "xrddiag: bench: %s\n", st.msg);
        xrdc_close(&c);
        return xrdc_shellcode(&st);
    }
    xrdc_timing_report(&c);
    xrdc_close(&c);

    /* Streams variant goes through xrdc_copy, which wires kXR_bind secondaries. */
    if (a->streams > 1) {
        xrdc_copy_opts co;
        xrdc_status    cst;
        char           tmpl[] = "/tmp/xrddiag-bench.XXXXXX";
        int            fd = mkstemp(tmpl);
        uint64_t       t0, t1;

        memset(&co, 0, sizeof(co));
        co.force = 1;
        co.silent = 1;
        co.streams = a->streams;
        snprintf(root_url, sizeof(root_url), "%s://%s:%d/%s",
                 a->conn.want_tls ? "roots" : "root", u.host, u.port, target);
        xrdc_status_clear(&cst);
        if (fd >= 0) {
            close(fd);
        }
        t0 = xrdc_mono_ns();
        if (xrdc_copy(root_url, tmpl, &co, &a->conn, &cst) != 0) {
            fprintf(stderr, "xrddiag: bench --streams: %s\n", cst.msg);
        } else {
            t1 = xrdc_mono_ns();
            double secs = (double) (t1 - t0) / 1e9;
            if (secs <= 0.0) { secs = 1e-9; }
            printf("  %-14s %lld bytes in %.3f s = %.1f MB/s (%d streams)\n",
                   "multi-stream", (long long) sti.size, secs,
                   (double) sti.size / 1e6 / secs, a->streams);
        }
        unlink(tmpl);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* topology — locate + redirect-loop convergence (+ optional /cluster) */
/* ------------------------------------------------------------------ */

static int
do_topology(const diag_args *a)
{
    xrdc_url    u;
    xrdc_conn   c;
    xrdc_status st;
    char        loc[4096];
    const char *qpath;

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (xrdc_connect(&c, &u, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }

    qpath = (u.path[0] != '\0') ? u.path : "/";
    printf("Topology of %s:%d\n", u.host, u.port);

    if (xrdc_locate(&c, qpath, loc, sizeof(loc), &st) == 0) {
        probe("locate", loc[0] != '\0', "%s -> %s", qpath, loc[0] ? loc : "(empty)");
    } else {
        probe("locate", 0, "%s", st.msg);
    }

    /* redirect-loop convergence: a nonexistent path must resolve to NotFound,
     * not exhaust the redirect budget (the cluster loop-guard regression test). */
    {
        xrdc_statinfo s;
        xrdc_status   nst;
        int           rc;
        xrdc_status_clear(&nst);
        rc = xrdc_stat(&c, "/nonexistent-xrddiag-probe-path", &s, &nst);
        probe("redirect-convergence", rc != 0 && nst.kxr == kXR_NotFound,
              "nonexistent path -> %s", rc != 0 ? xrdc_kxr_name(nst.kxr) : "SERVED?!");
    }

    if (a->cluster_url != NULL) {
        xrdc_url    cu;
        xrdc_status cst;
        char       *body = malloc(1u << 20);
        int         http = 0;
        xrdc_status_clear(&cst);
        if (body != NULL && xrdc_endpoint_parse(a->cluster_url, &cu, &cst) == 0 &&
            xrdc_http_get(cu.host, cu.port, cu.path[0] ? cu.path : "/", 5000,
                          &http, body, 1u << 20, NULL, &cst) == 0) {
            printf("  /cluster (HTTP %d):\n%s\n", http, body);
        } else {
            note("cluster-json", "unavailable: %s", cst.msg);
        }
        free(body);
    } else {
        note("cluster-json", "pass --cluster-url http://host:port/xrootd/api/v1/cluster");
    }

    xrdc_close(&c);
    return g_fails ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* status — pull /metrics and summarise                                */
/* ------------------------------------------------------------------ */

static int
do_status(const diag_args *a)
{
    xrdc_url    u;
    xrdc_status st;
    char       *body;
    int         http = 0, lines = 0, shown = 0;
    char       *line, *save;

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    body = malloc(1u << 20);
    if (body == NULL) {
        fprintf(stderr, "xrddiag: out of memory\n");
        return 51;
    }
    if (xrdc_http_get(u.host, a->metrics_port, "/metrics", 5000, &http, body,
                      1u << 20, NULL, &st) != 0) {
        fprintf(stderr, "xrddiag: GET %s:%d/metrics: %s\n",
                u.host, a->metrics_port, st.msg);
        free(body);
        return 51;
    }
    printf("Metrics from %s:%d (HTTP %d)\n", u.host, a->metrics_port, http);
    for (line = strtok_r(body, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        lines++;
        /* show the first handful of non-zero counters as a one-screen sample */
        if (shown < 20 && strstr(line, " 0") != line + (int) strlen(line) - 2) {
            printf("  %s\n", line);
            shown++;
        }
    }
    printf("  ... %d metric series total\n", lines);
    free(body);
    return lines > 0 ? 0 : 51;
}

/* ------------------------------------------------------------------ */
/* compare — root-vs-reference (size + dirlist set + md5)              */
/* ------------------------------------------------------------------ */

/* md5 of a remote file fetched over conn c, into hex[hexsz]. 0 / -1. */
static int
remote_md5(xrdc_conn *c, const char *path, char *hex, size_t hexsz, xrdc_status *st)
{
    char    tmpl[] = "/tmp/xrddiag-cmp.XXXXXX";
    int     fd = mkstemp(tmpl);
    int64_t got = 0;
    int     rc;

    if (fd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, 0, "mkstemp failed");
        return -1;
    }
    rc = download_to_fd(c, path, fd, &got, st);
    if (rc == 0) {
        rc = xrdc_cksum_fd(fd, XRDC_CK_MD5, hex, hexsz, st);
    }
    close(fd);
    unlink(tmpl);
    return rc;
}

/* Parse a "[http://]host[:port][/...]" WebDAV endpoint into host + port (8080). */
static void
parse_http_hostport(const char *s, char *host, size_t hsz, int *port)
{
    const char *p = s, *e;
    *port = 8080;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }
    e = p;
    while (*e != '\0' && *e != ':' && *e != '/') {
        e++;
    }
    {
        size_t n = (size_t) (e - p);
        if (n >= hsz) { n = hsz - 1; }
        memcpy(host, p, n);
        host[n] = '\0';
    }
    if (*e == ':') {
        *port = atoi(e + 1);
    }
}

/*
 * §15.6 cross-protocol consistency oracle: read the SAME object via root:// and
 * cleartext WebDAV (HTTP GET) and assert size + MD5 agree. The capability no
 * upstream client has — this project unifies the planes over one VFS, so a
 * divergence here is a real cross-protocol bug. S3 (SigV4) and HTTPS-davs
 * (TLS+chunked) planes are deferred — noted, not implemented.
 */
static int
do_compare_davs(const diag_args *a)
{
    xrdc_url      ua;
    xrdc_conn     ca;
    xrdc_status   st;
    char          dhost[256];
    int           dport;
    char          root_md5[64], davs_md5[64];
    char         *body;
    size_t        blen = 0;
    int           http = 0, fd;
    char          tmpl[] = "/tmp/xrddiag-davs.XXXXXX";

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(a->url, &ua, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (ua.path[0] == '\0' || strcmp(ua.path, "/") == 0) {
        fprintf(stderr, "xrddiag: compare --davs needs a file path in the URL\n");
        return 50;
    }
    parse_http_hostport(a->davs, dhost, sizeof(dhost), &dport);
    printf("Cross-protocol compare %s\n  root:// %s:%d   davs(http) %s:%d   path %s\n",
           a->url, ua.host, ua.port, dhost, dport, ua.path);

    if (xrdc_connect(&ca, &ua, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect %s:%d: %s\n", ua.host, ua.port, st.msg);
        return xrdc_shellcode(&st);
    }
    if (remote_md5(&ca, ua.path, root_md5, sizeof(root_md5), &st) != 0) {
        probe("root-read", 0, "%s", st.msg);
        xrdc_close(&ca);
        return 1;
    }
    xrdc_close(&ca);

    /* WebDAV plane: cleartext HTTP GET of the same logical path (binary-safe). */
    body = (char *) malloc(1u << 20);
    if (body == NULL) {
        fprintf(stderr, "xrddiag: out of memory\n");
        return 51;
    }
    xrdc_status_clear(&st);
    if (xrdc_http_get(dhost, dport, ua.path, 5000, &http, body, 1u << 20, &blen,
                      &st) != 0) {
        probe("davs-http", 0, "GET %s:%d%s: %s", dhost, dport, ua.path, st.msg);
        free(body);
        return 1;
    }
    probe("davs-http", http == 200, "HTTP %d for %s", http, ua.path);
    if (http != 200) {
        free(body);
        printf("Result: %d difference(s)\n", g_fails);
        return 1;
    }
    fd = mkstemp(tmpl);
    if (fd < 0 || (size_t) write(fd, body, blen) != blen
        || xrdc_cksum_fd(fd, XRDC_CK_MD5, davs_md5, sizeof(davs_md5), &st) != 0) {
        probe("davs-md5", 0, "local md5 failed");
        if (fd >= 0) { close(fd); unlink(tmpl); }
        free(body);
        return 1;
    }
    close(fd);
    unlink(tmpl);
    free(body);

    probe("davs-md5", strcmp(root_md5, davs_md5) == 0,
          "root=%s davs=%s", root_md5, davs_md5);
    note("s3 / https-davs", "deferred (needs SigV4 / HTTPS+chunked)");
    printf("Result: %d difference(s)\n", g_fails);
    return g_fails ? 1 : 0;
}

static int
do_compare(const diag_args *a)
{
    if (a->davs != NULL) {
        return do_compare_davs(a);
    }
    xrdc_url      ua, ub;
    xrdc_conn     ca, cb;
    xrdc_status   st;
    xrdc_statinfo sa, sb;

    if (a->ref_url == NULL) {
        fprintf(stderr, "xrddiag: compare needs --vs-reference <url>\n");
        return 50;
    }
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(a->url, &ua, &st) != 0 ||
        xrdc_endpoint_parse(a->ref_url, &ub, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (ua.path[0] == '\0' || strcmp(ua.path, "/") == 0) {
        fprintf(stderr, "xrddiag: compare needs a file/dir path in the URL\n");
        return 50;
    }
    if (xrdc_connect(&ca, &ua, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect A %s:%d: %s\n", ua.host, ua.port, st.msg);
        return xrdc_shellcode(&st);
    }
    if (xrdc_connect(&cb, &ub, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect B %s:%d: %s\n", ub.host, ub.port, st.msg);
        xrdc_close(&ca);
        return xrdc_shellcode(&st);
    }

    printf("Compare %s  vs  %s\n", a->url, a->ref_url);

    {
        xrdc_status sta, stb;
        const char *pa = ua.path;
        const char *pb = (ub.path[0] && strcmp(ub.path, "/")) ? ub.path : ua.path;
        int oka, okb;
        xrdc_status_clear(&sta);
        xrdc_status_clear(&stb);
        oka = xrdc_stat(&ca, pa, &sa, &sta) == 0;
        okb = xrdc_stat(&cb, pb, &sb, &stb) == 0;
        if (!oka || !okb) {
            probe("stat", 0, "A:%s B:%s", oka ? "ok" : sta.msg, okb ? "ok" : stb.msg);
            xrdc_close(&ca);
            xrdc_close(&cb);
            return 1;
        }
        probe("size", sa.size == sb.size, "A=%lld B=%lld",
              (long long) sa.size, (long long) sb.size);

        if (sa.flags & kXR_isDir) {
            xrdc_dirent *ea = NULL, *eb = NULL;
            size_t       na = 0, nb = 0;
            int          eq = 1;
            if (xrdc_dirlist(&ca, pa, 0, &ea, &na, &sta) == 0 &&
                xrdc_dirlist(&cb, pb, 0, &eb, &nb, &stb) == 0) {
                if (na != nb) {
                    eq = 0;
                } else {
                    for (size_t i = 0; i < na && eq; i++) {
                        int hit = 0;
                        for (size_t j = 0; j < nb; j++) {
                            if (strcmp(ea[i].name, eb[j].name) == 0) { hit = 1; break; }
                        }
                        if (!hit) { eq = 0; }
                    }
                }
                probe("dirlist-set", eq, "A=%zu B=%zu entries", na, nb);
            } else {
                probe("dirlist-set", 0, "list failed");
            }
            free(ea);
            free(eb);
        } else {
            char ha[64], hb[64];
            xrdc_status ma, mb;
            xrdc_status_clear(&ma);
            xrdc_status_clear(&mb);
            if (remote_md5(&ca, pa, ha, sizeof(ha), &ma) == 0 &&
                remote_md5(&cb, pb, hb, sizeof(hb), &mb) == 0) {
                probe("md5", strcmp(ha, hb) == 0, "A=%s B=%s", ha, hb);
            } else {
                probe("md5", 0, "A:%s B:%s",
                      ma.kxr ? ma.msg : "ok", mb.kxr ? mb.msg : "ok");
            }
        }
    }

    xrdc_close(&ca);
    xrdc_close(&cb);
    printf("Result: %d difference(s)\n", g_fails);
    return g_fails ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* probe-robustness — gated adversarial auditor (§15.8)                */
/* ------------------------------------------------------------------ */

/*
 * Resolve host ONCE to a numeric IP and classify whether it is loopback. The
 * probe then connects to this SAME numeric IP (getaddrinfo on a literal address
 * is deterministic), so a DNS-rebind / localhost.attacker.com cannot slip a
 * non-loopback target past the gate between the check and the connect. 0 / -1.
 */
static int
resolve_once(const char *host, int port, char *ip, size_t ipsz, int *is_loop,
             xrdc_status *st)
{
    struct addrinfo  hints, *res = NULL;
    char             portstr[16];
    int              gai;

    memset(&hints, 0, sizeof(hints));
    /* Honor a session-wide IPv6→IPv4 demotion (netpref.c) for consistency with
     * every other connect path: AF_UNSPEC normally, AF_INET once this process
     * has fallen back to IPv4-only. */
    hints.ai_family   = xrdc_netpref_family();
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);

    gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0 || res == NULL) {
        xrdc_status_set(st, XRDC_ESOCK, 0, "resolve %s: %s", host,
                        gai_strerror(gai));
        return -1;
    }
    *is_loop = 0;
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *) res->ai_addr;
        *is_loop = ((ntohl(s4->sin_addr.s_addr) >> 24) == 127);   /* 127.0.0.0/8 */
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) res->ai_addr;
        *is_loop = IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr);
    }
    getnameinfo(res->ai_addr, res->ai_addrlen, ip, (socklen_t) ipsz, NULL, 0,
                NI_NUMERICHOST);
    freeaddrinfo(res);
    return 0;
}

/* Connect a fresh session to the (numeric) probe target, with a bounded per-probe
 * deadline so a wedged/abusive exchange can never hang the auditor. 0 / -1. */
static int
probe_open(xrdc_conn *c, const char *urlbuf, const diag_args *a, int tmo,
           xrdc_status *st)
{
    xrdc_url cu;
    if (xrdc_endpoint_parse(urlbuf, &cu, st) != 0) {
        return -1;
    }
    if (xrdc_connect(c, &cu, &a->conn, st) != 0) {
        return -1;
    }
    c->io.timeout_ms = tmo;
    return 0;
}

/*
 * Write a (possibly malformed) 24-byte header + body bytes straight onto the wire
 * — bypassing xrdc_send so we can lie about dlen / use a bad opcode — then read
 * one response. Returns 1 if the server REJECTED the abuse (kXR_error, an
 * unexpected status, or a closed/timed-out connection), 0 if it SERVED it
 * (kXR_ok/oksofar — a bug), -1 on our own write failure.
 */
static int
raw_send_expect_reject(xrdc_conn *c, const uint8_t hdr24[24],
                       const uint8_t *body, uint32_t bodylen,
                       int lie_dlen, uint32_t fake_dlen)
{
    uint8_t     hdr[24];
    xrdc_status st;
    uint16_t    status = 0;
    uint8_t    *rb = NULL;
    uint32_t    rl = 0, wire_dlen;
    int         rc;

    memcpy(hdr, hdr24, 24);
    hdr[0] = 0x7e; hdr[1] = 0x01;   /* arbitrary streamid (recv accepts any) */
    wire_dlen = lie_dlen ? fake_dlen : bodylen;
    hdr[20] = (uint8_t) (wire_dlen >> 24);
    hdr[21] = (uint8_t) (wire_dlen >> 16);
    hdr[22] = (uint8_t) (wire_dlen >> 8);
    hdr[23] = (uint8_t) wire_dlen;

    xrdc_status_clear(&st);
    if (xrdc_write_full(&c->io, hdr, 24, &st) != 0) {
        return -1;
    }
    if (bodylen > 0 && body != NULL) {
        if (xrdc_write_full(&c->io, body, bodylen, &st) != 0) {
            return -1;
        }
    }
    rc = xrdc_recv(c, 0xffff, &status, &rb, &rl, &st);
    free(rb);
    if (rc != 0) {
        return 1;   /* kXR_error / closed / timeout → rejected cleanly */
    }
    return (status == kXR_ok || status == kXR_oksofar) ? 0 : 1;
}

static int
do_probe_robustness(const diag_args *a)
{
    xrdc_url      u;
    xrdc_status   st;
    char          ip[128];
    char          urlbuf[300];
    int           is_loop = 0, tmo;

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (resolve_once(u.host, u.port, ip, sizeof(ip), &is_loop, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 51;
    }
    /* Safety gate: this is a fuzzing-class tool. Refuse a non-loopback resolved
     * address unless the operator explicitly asserts authorisation. */
    if (!is_loop && !a->authorized) {
        fprintf(stderr,
                "xrddiag: refusing to fuzz non-loopback target %s (%s) — this is "
                "an adversarial auditor; re-run with --i-am-authorized only "
                "against hosts you are authorised to test.\n", u.host, ip);
        return 3;
    }

    tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 5000;
    snprintf(urlbuf, sizeof(urlbuf), "%s://%s:%d/",
             a->conn.want_tls ? "roots" : "root", ip, u.port);
    printf("probe-robustness %s (%s:%d)%s\n", u.host, ip, u.port,
           is_loop ? "" : " [AUTHORISED non-loopback]");
    printf("Probes (each must be REJECTED cleanly, server must survive):\n");

    /* P1 — path-escape (well-formed; must be refused AND the conn survive). */
    {
        xrdc_conn     c;
        xrdc_status   cs;
        xrdc_statinfo si;
        xrdc_status_clear(&cs);
        if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
            xrdc_status   est;
            xrdc_statinfo s2;
            xrdc_status   s2t;
            int           served, alive;
            xrdc_status_clear(&est);
            xrdc_status_clear(&s2t);
            served = (xrdc_stat(&c, "/../../../../../../etc/passwd", &si, &est) == 0);
            /* survive: a normal stat still completes (transport intact). */
            alive = (xrdc_stat(&c, "/", &s2, &s2t) == 0) || (s2t.kxr > 0);
            probe("path-escape", !served && alive,
                  served ? "ESCAPE SERVED — confinement broken!"
                         : "refused (%s), connection alive",
                  served ? "" : xrdc_kxr_name(est.kxr));
            xrdc_close(&c);
        } else {
            probe("path-escape", 0, "connect: %s", cs.msg);
        }
    }

    /* P2 — unknown opcode (must be refused). */
    {
        xrdc_conn   c;
        xrdc_status cs;
        xrdc_status_clear(&cs);
        if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
            uint8_t hdr[24];
            int     v;
            memset(hdr, 0, sizeof(hdr));
            hdr[2] = 0x27; hdr[3] = 0x0f;   /* requestid 9999 = not a kXR_* op */
            v = raw_send_expect_reject(&c, hdr, NULL, 0, 0, 0);
            probe("bad-opcode", v == 1,
                  v == 0 ? "SERVED an unknown opcode!" : "rejected");
            xrdc_close(&c);
        } else {
            probe("bad-opcode", 0, "connect: %s", cs.msg);
        }
    }

    /* P3 — oversized dlen (header claims ~1 GiB, no body): must reject/close,
     *      never buffer it (the server caps payload). */
    {
        xrdc_conn   c;
        xrdc_status cs;
        xrdc_status_clear(&cs);
        if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
            uint8_t hdr[24];
            int     v;
            memset(hdr, 0, sizeof(hdr));
            hdr[2] = (uint8_t) (kXR_stat >> 8);
            hdr[3] = (uint8_t) (kXR_stat & 0xff);
            v = raw_send_expect_reject(&c, hdr, NULL, 0, 1, 0x40000000u);
            probe("oversized-dlen", v == 1,
                  v == 0 ? "accepted a 1 GiB dlen!" : "rejected/closed");
            xrdc_close(&c);
        } else {
            probe("oversized-dlen", 0, "connect: %s", cs.msg);
        }
    }

    /* P4 — read on a bogus file handle with a huge length (OOB): must reject. */
    {
        xrdc_conn   c;
        xrdc_status cs;
        xrdc_status_clear(&cs);
        if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
            uint8_t hdr[24];
            int     v;
            memset(hdr, 0, sizeof(hdr));
            hdr[2] = (uint8_t) (kXR_read >> 8);
            hdr[3] = (uint8_t) (kXR_read & 0xff);
            memset(hdr + 4, 0xff, 4);            /* fhandle = never-opened */
            hdr[16] = 0x7f; hdr[17] = 0xff;      /* rlen = 0x7fffffff (huge) */
            hdr[18] = 0xff; hdr[19] = 0xff;
            v = raw_send_expect_reject(&c, hdr, NULL, 0, 0, 0);
            probe("oob-read", v == 1,
                  v == 0 ? "served a read on a bogus handle!" : "rejected");
            xrdc_close(&c);
        } else {
            probe("oob-read", 0, "connect: %s", cs.msg);
        }
    }

    /* P5 — truncated/slowloris partial header (must not crash the server). */
    {
        xrdc_conn   c;
        xrdc_status cs;
        xrdc_status_clear(&cs);
        if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
            uint8_t half[12] = { 0 };
            half[2] = (uint8_t) (kXR_stat >> 8);
            half[3] = (uint8_t) (kXR_stat & 0xff);
            (void) xrdc_write_full(&c.io, half, sizeof(half), &cs);
            probe("partial-frame", 1, "sent 12/24 header bytes then closed");
            xrdc_close(&c);   /* abandon mid-frame */
        } else {
            probe("partial-frame", 0, "connect: %s", cs.msg);
        }
    }

    /* Server-survives gate: a fresh session + stat must still work after the
     * battery — proves nothing above crashed or wedged the server. */
    {
        xrdc_conn     c;
        xrdc_status   cs;
        xrdc_statinfo si;
        xrdc_status_clear(&cs);
        if (probe_open(&c, urlbuf, a, tmo, &cs) == 0) {
            xrdc_status s2;
            int         alive;
            xrdc_status_clear(&s2);
            alive = (xrdc_stat(&c, "/", &si, &s2) == 0) || (s2.kxr > 0);
            probe("server-survives", alive,
                  alive ? "fresh session OK after battery"
                        : "server unreachable after battery!");
            xrdc_close(&c);
        } else {
            probe("server-survives", 0, "reconnect: %s", cs.msg);
        }
    }

    printf("Result: %d failure(s)\n", g_fails);
    return g_fails ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* replay — decode a .xrdcap offline, or re-issue it against a server  */
/* ------------------------------------------------------------------ */

static int
do_replay(const diag_args *a)
{
    xrdc_status st;
    int         rc;

    xrdc_status_clear(&st);
    if (a->playback_url != NULL) {
        rc = xrdc_capture_playback(a->url, a->playback_url, &a->conn, stdout, &st);
    } else {
        rc = xrdc_capture_replay(a->url, a->conn.wire_trace, stdout, &st);
    }
    if (rc != 0) {
        fprintf(stderr, "xrddiag: replay: %s\n", st.msg);
        return xrdc_shellcode(&st);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* remote-doctor — interrogate endpoint(s) to debug transfer problems  */
/* ------------------------------------------------------------------ */

#define DOC_GREEN  0
#define DOC_YELLOW 1
#define DOC_RED    2
#define DOC_MAXISS 8

/* Active-diagnosis verdicts map onto the same severity scale as the status rollup,
 * so a finding's verdict can escalate doctor_ep.status directly. */
#define DX_OK   DOC_GREEN
#define DX_WARN DOC_YELLOW
#define DX_FAIL DOC_RED
#define DOC_MAXDX 20

/* One classified result of an active probe against a remote subsystem. */
typedef struct {
    char probe[16];     /* subsystem id: auth/namespace/read/checksum/locate/load/write/stage */
    int  verdict;       /* DX_OK / DX_WARN / DX_FAIL */
    int  kxr;           /* the kXR_* code observed (0 if none / not a server error) */
    char cause[160];    /* root-cause classification (PII-free) */
    char remedy[200];   /* operator remediation (PII-free) */
} dx_finding;

/* Which protocol's transfer this endpoint's battery deep-dives. */
typedef enum {
    DXP_ROOT = 0,   /* root:// / roots:// (libxrdc) */
    DXP_HTTP,       /* http://  (cleartext XrdHttp/WebDAV GET) */
    DXP_HTTPS,      /* https:// (TLS XrdHttp GET) */
    DXP_DAVS,       /* davs:// / dav:// (WebDAV class-2 over TLS) */
    DXP_S3,         /* s3:// / s3s:// (S3 REST, SigV4) */
    DXP_CMS         /* cms:// (cluster manager: locate + redirect trace) */
} dx_proto;

typedef struct {
    dx_proto      proto;             /* which protocol battery produced this endpoint */
    char          host[256];
    int           port;
    int           connected;
    int           status;            /* DOC_GREEN/YELLOW/RED */
    xrdc_netfacts nf;                /* phases / family / TCP_INFO / flowlabel */
    int           tls_active;
    char          tls_ver[24], tls_cipher[48];
    char          auth[24];          /* chosen auth proto, or "anon" */
    int           gototls;           /* server advertised kXR_gotoTLS */
    unsigned      caps;              /* server_flags */
    int           have_xfer;
    int64_t       xfer_bytes;
    double        ttfb_ms, mbps;
    int           holders;           /* locate token count */
    int           ghost;             /* a located holder that would not serve */
    int           metrics_http;      /* /metrics HTTP status (0 = not pulled) */
    int           shedding;          /* /metrics shows kXR_wait / budget shedding */
    int           offline_seen;      /* read probe saw a kXR_offline (tape) file */
    int           nissues;
    char          issues[DOC_MAXISS][160];
    int           ndx;               /* active-diagnosis findings */
    dx_finding    dx[DOC_MAXDX];
} doctor_ep;

static void
doc_issue(doctor_ep *e, int sev, const char *fmt, ...)
{
    va_list ap;
    if (e->nissues >= DOC_MAXISS) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(e->issues[e->nissues], sizeof(e->issues[0]), fmt, ap);
    va_end(ap);
    e->nissues++;
    if (sev > e->status) {
        e->status = sev;
    }
}

/* Throughput probe over an established conn: TTFB (first read) + MB/s (whole file). */
static int
doctor_xfer(xrdc_conn *c, const char *path, double *ttfb_ms, double *mbps,
            int64_t *bytes)
{
    xrdc_file   f;
    xrdc_status st;
    uint8_t    *buf;
    int64_t     off = 0;
    uint64_t    t0, tf = 0, t1;

    xrdc_status_clear(&st);
    if (xrdc_file_open_read(c, path, &f, &st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1u << 20);
    if (buf == NULL) {
        xrdc_file_close(c, &f, &st);
        return -1;
    }
    t0 = xrdc_mono_ns();
    for (;;) {
        ssize_t r = xrdc_file_read(c, &f, off, buf, 1u << 20, &st);
        if (r < 0) { free(buf); xrdc_file_close(c, &f, &st); return -1; }
        if (tf == 0) { tf = xrdc_mono_ns(); }     /* time-to-first-byte */
        if (r == 0) { break; }
        off += r;
    }
    t1 = xrdc_mono_ns();
    free(buf);
    xrdc_file_close(c, &f, &st);
    *ttfb_ms = (double) (tf - t0) / 1e6;
    *bytes   = off;
    {
        double secs = (double) (t1 - t0) / 1e9;
        if (secs <= 0.0) { secs = 1e-9; }
        *mbps = (double) off / 1e6 / secs;
    }
    return 0;
}

/* /metrics signal: reachable? + any kXR_wait/budget shedding gauge nonzero. */
static void
doctor_metrics(const char *host, int port, doctor_ep *e)
{
    char       *body;
    xrdc_status st;
    int         http = 0;
    char       *line, *save;

    body = (char *) malloc(1u << 20);
    if (body == NULL) {
        return;
    }
    xrdc_status_clear(&st);
    if (xrdc_http_get(host, port, "/metrics", 4000, &http, body, 1u << 20, NULL,
                      &st) != 0) {
        free(body);
        return;
    }
    e->metrics_http = http;
    for (line = strtok_r(body, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == '#') {
            continue;
        }
        if (strstr(line, "kXR_wait") != NULL || strstr(line, "_wait_") != NULL
            || strstr(line, "budget") != NULL || strstr(line, "shed") != NULL) {
            /* nonzero counter at the end of the line ⇒ active shedding */
            char *sp = strrchr(line, ' ');
            if (sp != NULL && strtod(sp + 1, NULL) > 0.0) {
                e->shedding = 1;
            }
        }
    }
    free(body);
}

/* ------------------------------------------------------------------ */
/* active diagnosis — exercise subsystems, classify symptom → cause    */
/* ------------------------------------------------------------------ */

/*
 * WHAT: the symptom→cause rule table. Each row maps a (probe, kXR-code) pair to a
 *       verdict + a PII-free root cause + a remediation.
 * WHY:  turns a raw server status ("kXR_NotAuthorized on write") into an actionable
 *       diagnosis ("export is read-only → enable allow_write"). The mapping is keyed on
 *       BOTH the probe and the code because the same code means different things per
 *       subsystem (NotAuthorized on read = ACL; on write = read-only/scope).
 * HOW:  dx_classify scans top-to-bottom for the first row whose probe matches (or is the
 *       NULL wildcard) and whose kxr matches (or is the DX_ANY wildcard). Unmatched codes
 *       fall back to a generic finding so we never invent guidance we are unsure of.
 */
#define DX_ANY (-9999)

typedef struct {
    const char *probe;   /* subsystem id, or NULL = any probe */
    int         kxr;     /* kXR_* code, or DX_ANY = any code */
    int         sev;     /* DX_WARN / DX_FAIL */
    const char *cause;
    const char *remedy;
} dx_rule;

static const dx_rule DX_RULES[] = {
    /* --- auth / authorization --- */
    { "auth", kXR_NotAuthorized, DX_FAIL,
      "authentication/authorization rejected",
      "check the client credential and that its auth protocol matches the server's &P= offer" },
    { "auth", kXR_AuthFailed, DX_FAIL,
      "authentication handshake failed (bad/invalid credential)",
      "verify the token signature/issuer or GSI proxy chain; check clock sync" },

    /* --- namespace (export root) --- */
    { "namespace", kXR_NotFound, DX_FAIL,
      "export root not found (xrootd_root misconfigured or unmounted)",
      "verify xrootd_root points to an existing, mounted, readable directory" },
    { "namespace", kXR_NotAuthorized, DX_FAIL,
      "listing the export root is denied (ACL/scope)",
      "check path ACLs / token scope for the root path" },
    { "namespace", kXR_IOError, DX_FAIL,
      "I/O error reading the export root (filesystem fault)",
      "check server storage health (dmesg/SMART); verify the mount is responsive" },

    /* --- read path --- */
    { "read", kXR_NotAuthorized, DX_FAIL,
      "read denied (ACL or token read scope)",
      "check the read scope / VO ACL for the path" },
    { "read", kXR_IOError, DX_FAIL,
      "server-side read I/O error",
      "check server storage health; the backing file/device may be faulty" },
    { "read", kXR_NotFound, DX_WARN,
      "file vanished between locate and open (namespace race/inconsistency)",
      "re-check the path; flush any stale redirect/namespace cache" },
    { "read", kXR_NoMemory, DX_FAIL,
      "server out of memory on read (budget shed)",
      "retry later; raise xrootd_memory_pool_size or lower concurrency/read size" },
    { "read", kXR_Overloaded, DX_WARN,
      "server overloaded on read",
      "retry with backoff; the server is at a connection/request cap" },

    /* --- checksum integrity --- */
    { "checksum", kXR_Unsupported, DX_WARN,
      "server does not support checksum query",
      "informational; checksum verification unavailable on this server" },

    /* --- locate / replicas --- */
    { "locate", kXR_NotFound, DX_WARN,
      "file not found, or no replica registered for the path",
      "verify the path exists; check the CMS/manager registry for replicas" },
    { "locate", kXR_noserver, DX_FAIL,
      "no data server available for the path",
      "bring a data server online; check the CMS/manager registry" },

    /* --- write path (gated) --- */
    { "write", kXR_fsReadOnly, DX_FAIL,
      "export is read-only (allow_write off or filesystem mounted ro)",
      "enable xrootd_allow_write, or direct writes to a read-write replica" },
    { "write", kXR_NotAuthorized, DX_FAIL,
      "write denied (token lacks write scope, or ACL)",
      "obtain a credential with write scope; check the write ACL for the path" },
    { "write", kXR_overQuota, DX_FAIL,
      "quota exceeded",
      "free space or raise the user/group quota" },
    { "write", kXR_NoSpace, DX_FAIL,
      "no space left on the export filesystem",
      "free disk space on the server export" },
    { "write", kXR_IOError, DX_FAIL,
      "server-side write I/O error",
      "check server storage health and that the export is writable" },
};

/* Append a classified finding; escalate the endpoint's status to its severity. */
static void
dx_record(doctor_ep *e, const char *probe, int verdict, int kxr,
          const char *cause, const char *remedy)
{
    dx_finding *f;
    if (e->ndx >= DOC_MAXDX) {
        return;
    }
    f = &e->dx[e->ndx++];
    snprintf(f->probe, sizeof(f->probe), "%s", probe);
    f->verdict = verdict;
    f->kxr     = kxr;
    snprintf(f->cause, sizeof(f->cause), "%s", cause ? cause : "");
    snprintf(f->remedy, sizeof(f->remedy), "%s", remedy ? remedy : "");
    if (verdict > e->status) {
        e->status = verdict;
    }
}

/*
 * Classify a failed probe (st->kxr) into a finding via DX_RULES, with a graceful
 * generic fallback for codes we have no specific rule for. A successful probe
 * (kxr==0, return 0 → caller records DX_OK) is handled by the caller.
 */
static void
dx_record_status(doctor_ep *e, const char *probe, const xrdc_status *st)
{
    size_t i;
    int    kxr = st ? st->kxr : 0;
    for (i = 0; i < sizeof(DX_RULES) / sizeof(DX_RULES[0]); i++) {
        const dx_rule *r = &DX_RULES[i];
        if (r->probe != NULL && strcmp(r->probe, probe) != 0) {
            continue;
        }
        if (r->kxr != DX_ANY && r->kxr != kxr) {
            continue;
        }
        dx_record(e, probe, r->sev, kxr, r->cause, r->remedy);
        return;
    }
    {
        /* generic fallback — name the code, give conservative guidance. */
        char cause[160];
        if (kxr > 0) {
            snprintf(cause, sizeof(cause), "%s probe failed: server returned %s",
                     probe, xrdc_kxr_name(kxr));
        } else {
            /* PII: never echo st->msg — server wire text may carry a path. */
            snprintf(cause, sizeof(cause), "%s probe failed (local/transport error)",
                     probe);
        }
        dx_record(e, probe, DX_FAIL, kxr, cause,
                  "inspect the server logs for this operation");
    }
}

/* Is the target a loopback host? Write-mutation probes run unconditionally only here;
 * for any other host they additionally require the explicit --i-am-authorized gate. */
static int
dx_is_loopback(const char *host)
{
    /* Exact match only — a prefix like "127." would match "127.attacker.com" and
     * wrongly enable mutating probes on a remote host. Anything not exactly a
     * loopback literal must pass --i-am-authorized instead. */
    return host != NULL && (strcmp(host, "127.0.0.1") == 0
        || strcmp(host, "localhost") == 0 || strcmp(host, "::1") == 0);
}

/* auth posture: did we connect anonymously to a server that advertises auth? */
static void
dx_probe_auth(const xrdc_conn *c, doctor_ep *e)
{
    int anon = (c->diag.chosen_auth == NULL);
    if (anon && c->sec_list[0] != '\0') {
        dx_record(e, "auth", DX_WARN, 0,
                  "server advertises auth but the client connected anonymously",
                  "provide matching credentials (--auth + token/proxy) if operations are denied");
    } else {
        dx_record(e, "auth", DX_OK, 0,
                  anon ? "anonymous (server offered no auth)" : "authenticated", "");
    }
}

/* namespace: the export root must stat as a directory and be listable. */
static void
dx_probe_namespace(xrdc_conn *c, doctor_ep *e)
{
    xrdc_statinfo si;
    xrdc_status   st;
    xrdc_dirent  *ents = NULL;
    size_t        n = 0;

    xrdc_status_clear(&st);
    if (xrdc_stat(c, "/", &si, &st) != 0) {
        dx_record_status(e, "namespace", &st);
        return;
    }
    xrdc_status_clear(&st);
    if (xrdc_dirlist(c, "/", 0, &ents, &n, &st) != 0) {
        dx_record_status(e, "namespace", &st);
        return;
    }
    {
        /* Count visible (non-dot) entries — the server keeps its own dotfiles
         * (e.g. a checkpoint-recovery lock) in the root, so a naive count is
         * never zero; only an absence of real data is a meaningful signal. */
        size_t i, visible = 0;
        for (i = 0; i < n; i++) {
            if (ents[i].name[0] != '.') { visible++; }
        }
        free(ents);
        if (visible == 0) {
            dx_record(e, "namespace", DX_WARN, 0,
                      "export root has no visible files (empty or wrong xrootd_root)",
                      "confirm data is present under the configured export root");
        } else {
            dx_record(e, "namespace", DX_OK, 0, "export root listable", "");
        }
    }
}

/*
 * read path: stat the target (note kXR_offline = on tape), then open it and read one
 * block. A failure is classified by the (read, kxr) rule; offline is a tape signal.
 */
static void
dx_probe_read(xrdc_conn *c, const char *target, doctor_ep *e)
{
    xrdc_statinfo si;
    xrdc_status   st;
    xrdc_file     f;

    xrdc_status_clear(&st);
    if (xrdc_stat(c, target, &si, &st) != 0) {
        dx_record_status(e, "read", &st);
        return;
    }
    if (si.flags & kXR_offline) {
        e->offline_seen = 1;
        dx_record(e, "read", DX_WARN, 0, "file is offline (on tape/cache, not staged)",
                  "issue a stage/prepare and retry after recall (use --allow-write for an active stage probe)");
        return;
    }
    xrdc_status_clear(&st);
    if (xrdc_file_open_read(c, target, &f, &st) != 0) {
        dx_record_status(e, "read", &st);
        return;
    }
    {
        uint8_t     buf[4096];   /* stack-backed: a read probe proves the path, no malloc */
        xrdc_status rst;
        ssize_t     r;
        xrdc_status_clear(&rst);
        r = xrdc_file_read(c, &f, 0, buf, sizeof(buf), &rst);
        if (r < 0) {
            xrdc_file_close(c, &f, &st);
            dx_record_status(e, "read", &rst);
            return;
        }
    }
    xrdc_file_close(c, &f, &st);
    dx_record(e, "read", DX_OK, 0, "read path healthy", "");
}

/*
 * checksum integrity: compare the server's advertised checksum against one recomputed
 * locally from the bytes we downloaded. A disagreement means a stale checksum DB or
 * on-disk corruption — a class of bug only a cross-check can surface.
 */
static void
dx_probe_checksum(xrdc_conn *c, const char *target, doctor_ep *e)
{
    char        srv[160], loc[160];
    xrdc_status st;
    int         fd;
    char        tmpl[] = "/tmp/xrddiag-dx.XXXXXX";
    int64_t     got = 0;

    /* Request adler32 (the client can recompute it) and compare the bare hex,
     * mirroring the proven `check` checksum-works probe. */
    xrdc_status_clear(&st);
    if (xrdc_query_cksum(c, target, "adler32", srv, sizeof(srv), &st) != 0) {
        if (st.kxr == kXR_Unsupported) {
            dx_record_status(e, "checksum", &st);
        }
        return;   /* server simply doesn't expose a checksum — not a problem */
    }
    fd = mkstemp(tmpl);
    if (fd < 0) {
        return;
    }
    xrdc_status_clear(&st);
    if (download_to_fd(c, target, fd, &got, &st) == 0
        && xrdc_cksum_fd(fd, XRDC_CK_ADLER32, loc, sizeof(loc), &st) == 0) {
        if (strcmp(srv, loc) == 0) {
            dx_record(e, "checksum", DX_OK, 0, "server checksum matches read data", "");
        } else {
            dx_record(e, "checksum", DX_FAIL, 0,
                      "server checksum disagrees with the bytes read (stale checksum DB or data corruption)",
                      "recompute/repair the server checksum; verify storage integrity");
        }
    }
    close(fd);
    unlink(tmpl);
}

/*
 * write path (GATED): create a unique temp dir, write+read-back a small object, verify
 * byte-exactness, then clean up. The failure code pins the cause precisely
 * (kXR_fsReadOnly = read-only export, kXR_NotAuthorized = no write scope, quota/space).
 * Always reverses its own mutations; bounded; never touches user data paths.
 */
static void
dx_probe_write(xrdc_conn *c, doctor_ep *e)
{
    char        dir[96], path[160];
    xrdc_status st;
    xrdc_file   f;
    const char  payload[] = "xrddiag-remote-doctor-write-probe\n";
    int         wrote = 0;

    /* pid + monotonic clock makes the temp namespace collision-proof across runs
     * and pid reuse, so the probe never reuses or fights a pre-existing directory. */
    snprintf(dir, sizeof(dir), "/.xrddiag-dx-%ld-%llx", (long) getpid(),
             (unsigned long long) xrdc_mono_ns());
    snprintf(path, sizeof(path), "%s/probe.tmp", dir);

    xrdc_status_clear(&st);
    if (xrdc_mkdir(c, dir, 0700, 0, &st) != 0) {
        dx_record_status(e, "write", &st);
        return;
    }
    xrdc_status_clear(&st);
    if (xrdc_file_open_write(c, path, 1 /*force*/, 0 /*posc*/, &f, &st) != 0) {
        dx_record_status(e, "write", &st);
        xrdc_rmdir(c, dir, &st);
        return;
    }
    xrdc_status_clear(&st);
    if (xrdc_file_write(c, &f, 0, payload, sizeof(payload) - 1, &st) == 0) {
        wrote = 1;
    }
    {
        /* a close failure means the server never durably committed the write. */
        xrdc_status cst;
        xrdc_status_clear(&cst);
        if (xrdc_file_close(c, &f, &cst) != 0 && wrote) {
            wrote = 0;
            st = cst;
        }
    }

    if (!wrote) {
        dx_record_status(e, "write", &st);
    } else {
        /* read back + verify byte-exactness */
        xrdc_file   rf;
        uint8_t     rb[64];
        ssize_t     rn = -1;
        xrdc_status rst;
        xrdc_status_clear(&rst);
        if (xrdc_file_open_read(c, path, &rf, &rst) == 0) {
            rn = xrdc_file_read(c, &rf, 0, rb, sizeof(rb), &rst);
            xrdc_file_close(c, &rf, &rst);
        }
        if (rn == (ssize_t) (sizeof(payload) - 1)
            && memcmp(rb, payload, sizeof(payload) - 1) == 0) {
            dx_record(e, "write", DX_OK, 0, "write path healthy (write/read-back verified)", "");
        } else {
            dx_record(e, "write", DX_FAIL, 0,
                      "write succeeded but read-back did not match (durability/consistency fault)",
                      "check the server write-through/cache flush path and storage backend");
        }
    }
    /* always clean up our mutations; warn (no silent residue) if the dir survives. */
    xrdc_status_clear(&st);
    xrdc_rm(c, path, &st);
    xrdc_status_clear(&st);
    if (xrdc_rmdir(c, dir, &st) != 0) {
        dx_record(e, "write", DX_WARN, st.kxr,
                  "write-probe test directory could not be removed",
                  "remove the leftover write-probe directory under the export root");
    }
}

/*
 * stage path (GATED, conditional): only if the read probe saw an offline file — request
 * a recall via kXR_prepare and report whether the server accepted the stage request.
 */
static void
dx_probe_stage(xrdc_conn *c, const char *target, doctor_ep *e)
{
    const char *paths[1];
    char        out[256];
    xrdc_status st;

    paths[0] = target;
    xrdc_status_clear(&st);
    if (xrdc_prepare(c, paths, 1, 0, 0, 0, out, sizeof(out), &st) == 0) {
        dx_record(e, "stage", DX_OK, 0, "stage/prepare request accepted by the server",
                  "wait for the recall to complete, then re-read");
    } else {
        dx_record_status(e, "stage", &st);
    }
}

/* ------------------------------------------------------------------ */
/* auth/permissions suite (--auth-suite) — differential authZ testing  */
/* ------------------------------------------------------------------ */

/* base64url-encode (no padding) into out[outsz] — to assemble synthetic JWTs for
 * negative tests. Returns 0, or -1 if the encoded form would not fit (the caller
 * then skips the test rather than emitting a truncated token). */
static int
dx_b64url_enc(const unsigned char *in, size_t n, char *out, size_t outsz)
{
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i, o = 0;
    if ((n + 2) / 3 * 4 + 1 > outsz) {     /* encoded length + NUL must fit */
        return -1;
    }
    for (i = 0; i + 3 <= n; i += 3) {
        uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i+1] << 8) | in[i+2];
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];  out[o++] = T[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t) in[i] << 16;
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63];
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i+1] << 8);
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];
    }
    out[o] = '\0';
    return 0;
}

/* Build "<b64url(header)>.<b64url(payload)>.<sig>" into out. 0 / -1 on overflow. */
static int
dx_make_jwt(const char *header, const char *payload, const char *sig,
            char *out, size_t outsz)
{
    char h[192], p[320];   /* sized for the short fixed probe header/payload below */
    if (dx_b64url_enc((const unsigned char *) header, strlen(header), h, sizeof(h)) != 0
        || dx_b64url_enc((const unsigned char *) payload, strlen(payload), p, sizeof(p)) != 0) {
        return -1;
    }
    if (strlen(h) + strlen(p) + strlen(sig) + 3 > outsz) {
        return -1;
    }
    snprintf(out, outsz, "%s.%s.%s", h, p, sig);
    return 0;
}

/*
 * Open a scoped diagnostic connection: a copy of the base opts with force_anon
 * and/or a specific bearer token (token_override, NULL = use the env as-is) and
 * an optional forced auth protocol. Saves/restores $BEARER_TOKEN around the call
 * so the credential matrix never leaks between probes. 0 on connect, -1 + *st.
 */
static int
dx_connect_as(const diag_args *a, const xrdc_url *u, int force_anon,
              const char *token_override, const char *auth_force,
              xrdc_conn *c, xrdc_status *st)
{
    xrdc_opts opts = a->conn;
    char     *saved = NULL;
    int       had = 0;
    int       rc;

    opts.force_anon = force_anon;
    if (auth_force != NULL) {
        opts.auth_force = auth_force;
    }
    if (token_override != NULL) {
        const char *cur = getenv("BEARER_TOKEN");
        if (cur != NULL) { saved = strdup(cur); had = (saved != NULL); }
        setenv("BEARER_TOKEN", token_override, 1);  /* checked first in discovery */
    }
    xrdc_status_clear(st);
    rc = xrdc_connect(c, u, &opts, st);
    if (token_override != NULL) {
        if (had) { setenv("BEARER_TOKEN", saved, 1); free(saved); }
        else     { unsetenv("BEARER_TOKEN"); }
    }
    return rc;
}

/*
 * authz-anon: open a force_anon session (login, NO credential), learn the server's
 * advertised auth from its &P= list, and on an auth-REQUIRED server assert that
 * unauthenticated stat/read is DENIED. A served op on an auth-advertising server is
 * the auth-bypass smoking gun. Writes the discovered sec list to *sec_out so the
 * caller can run the token tests. Returns 1 if the session was established.
 */
static int
dx_authz_anon(const diag_args *a, const xrdc_url *u, const char *target,
              int have_target, char *sec_out, size_t sec_sz, doctor_ep *e)
{
    xrdc_conn     c;
    xrdc_status   st;
    xrdc_statinfo si;
    int           served = 0;

    if (sec_out != NULL && sec_sz > 0) { sec_out[0] = '\0'; }
    if (dx_connect_as(a, u, 1, NULL, NULL, &c, &st) != 0) {
        dx_record(e, "authz-anon", DX_WARN, st.kxr,
                  "could not establish even an unauthenticated session (cannot assess auth posture)",
                  "check reachability and retry when the server is up");
        return 0;
    }
    if (sec_out != NULL && sec_sz > 0) {
        snprintf(sec_out, sec_sz, "%s", c.sec_list);
    }
    if (c.sec_list[0] == '\0') {
        xrdc_close(&c);
        dx_record(e, "authz-anon", DX_OK, 0,
                  "server requires no authentication (anonymous by design)", "");
        return 1;
    }
    xrdc_status_clear(&st);
    if (xrdc_stat(&c, "/", &si, &st) == 0) {
        served = 1;
    }
    if (!served && have_target) {
        xrdc_file   f;
        xrdc_status ost;
        xrdc_status_clear(&ost);
        if (xrdc_file_open_read(&c, target, &f, &ost) == 0) {
            served = 1;
            xrdc_file_close(&c, &f, &ost);
        }
    }
    xrdc_close(&c);
    if (served) {
        dx_record(e, "authz-anon", DX_FAIL, 0,
                  "an unauthenticated client was served data/metadata on an auth-required server (auth bypass)",
                  "the server is not enforcing authentication — audit the auth config and the server build");
    } else {
        dx_record(e, "authz-anon", DX_OK, st.kxr,
                  "unauthenticated access correctly denied", "");
    }
    return 1;
}

/*
 * authz-forged: present a structurally-valid but cryptographically-invalid bearer
 * token (garbage signature, or alg:none). A correct server rejects it at kXR_auth
 * (connect fails). A connect SUCCESS means the server accepted an unverifiable
 * token — exactly the broken-signature-verification class of regression.
 */
static void
dx_authz_forged(const diag_args *a, const xrdc_url *u, const char *probe,
                const char *bad_token, doctor_ep *e)
{
    xrdc_conn   c;
    xrdc_status st;

    if (dx_connect_as(a, u, 0, bad_token, "ztn", &c, &st) == 0) {
        xrdc_close(&c);
        dx_record(e, probe, DX_FAIL, 0,
                  "server ACCEPTED an invalid bearer token (broken token verification)",
                  "CRITICAL: invalid tokens must be rejected — patch/upgrade the server token auth");
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, probe, DX_OK, st.kxr,
                  "invalid bearer token correctly rejected", "");
    } else {
        /* connect failed for a non-auth reason (e.g. transport) — we did NOT get
         * to test token verification; do not report a false pass. */
        dx_record(e, probe, DX_WARN, st.kxr,
                  "could not complete the forged-token test (server unreachable mid-test)",
                  "retry when the server is reachable");
    }
}

/*
 * authz-expired: present the operator's REAL (validly-signed) token when it has
 * already expired. A correct server rejects on the exp claim. Acceptance means
 * expiry is not enforced.
 */
static void
dx_authz_expired(const diag_args *a, const xrdc_url *u, const char *tok, doctor_ep *e)
{
    xrdc_conn   c;
    xrdc_status st;

    if (dx_connect_as(a, u, 0, tok, "ztn", &c, &st) == 0) {
        xrdc_close(&c);
        dx_record(e, "authz-expired", DX_FAIL, 0,
                  "server ACCEPTED an expired bearer token",
                  "CRITICAL: the server is not enforcing token expiry (exp claim)");
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, "authz-expired", DX_OK, st.kxr,
                  "expired bearer token correctly rejected", "");
    } else {
        dx_record(e, "authz-expired", DX_WARN, st.kxr,
                  "could not complete the expired-token test (server unreachable mid-test)",
                  "retry when the server is reachable");
    }
}

/*
 * authz-scope (GATED --allow-write): present a read-only token and attempt a write
 * in a unique temp namespace. A correct server denies (kXR_NotAuthorized). A write
 * that SUCCEEDS means token write-scope is not enforced — privilege escalation.
 * Always reverses any mutation.
 */
static void
dx_authz_scope(const diag_args *a, const xrdc_url *u, const char *tok, doctor_ep *e)
{
    xrdc_conn   c;
    xrdc_status st;
    char        dir[96];

    if (dx_connect_as(a, u, 0, tok, "ztn", &c, &st) != 0) {
        dx_record(e, "authz-scope", DX_WARN, st.kxr,
                  "read-only token did not authenticate; cannot test write-scope enforcement", "");
        return;
    }
    snprintf(dir, sizeof(dir), "/.xrddiag-az-%ld-%llx", (long) getpid(),
             (unsigned long long) xrdc_mono_ns());

    /*
     * mkdir IS a write operation: a read-only token must be denied it. Testing it
     * directly avoids the mkdir-then-open ambiguity (if mkdir is denied, a later
     * open-write fails with NotFound, not a scope verdict). The DENIAL CODE is
     * decisive: kXR_NotAuthorized = scope/ACL enforced (correct); kXR_fsReadOnly =
     * read-only export, so we CANNOT isolate scope enforcement (inconclusive);
     * SUCCESS = a read-only token mutated the namespace (scope NOT enforced).
     */
    xrdc_status_clear(&st);
    if (xrdc_mkdir(&c, dir, 0700, 0, &st) == 0) {
        dx_record(e, "authz-scope", DX_FAIL, 0,
                  "a read-only token was allowed to create a directory (token scope not enforced)",
                  "CRITICAL: the server is not enforcing token write-scope");
        xrdc_status_clear(&st);
        xrdc_rmdir(&c, dir, &st);                 /* reverse our mutation */
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, "authz-scope", DX_OK, st.kxr,
                  "write (mkdir) correctly denied for a read-only token (scope/ACL enforced)", "");
    } else if (st.kxr == kXR_fsReadOnly) {
        dx_record(e, "authz-scope", DX_WARN, st.kxr,
                  "export is read-only (allow_write off) — cannot isolate token write-scope enforcement",
                  "re-run against a read-write export to test token write-scope");
    } else {
        dx_record(e, "authz-scope", DX_WARN, st.kxr,
                  "write probe failed for an unexpected reason; scope enforcement unclear",
                  "inspect the server logs for this operation");
    }
    xrdc_close(&c);
}

/*
 * The full auth/permissions suite. Opens its own scoped connections (the credential
 * matrix) — does not reuse the primary. Read-only assertions always run; the
 * write-scope assertion is gated like the write probe. PII-free: only verdicts +
 * kXR codes are recorded, never token/cert/scope contents.
 */
static void
doctor_auth_suite(const diag_args *a, const xrdc_url *u, const char *target,
                  int have_target, doctor_ep *e)
{
    char  sec_list[256];
    int   ztn_adv;
    char *tok;

    /* 1) anonymous access must be denied on an auth-required server — this also
     *    discovers the server's advertised auth (&P=) from a force_anon session. */
    dx_authz_anon(a, u, target, have_target, sec_list, sizeof(sec_list), e);
    ztn_adv = (strstr(sec_list, "ztn") != NULL);

    /* 2,3) forged-credential rejection — only if the server takes bearer tokens. */
    if (ztn_adv) {
        char fsig[1024], fnone[1024];
        /* No kid: a kid the server doesn't know would be rejected at key SELECTION,
         * short-circuiting the signature check — we want the server to reach
         * signature verification (and reject the garbage sig) so the test actually
         * exercises signature verification on typical single-key deployments. */
        if (dx_make_jwt(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
                "{\"iss\":\"https://xrddiag.invalid\",\"sub\":\"xrddiag-probe\","
                "\"scope\":\"storage.read:/ storage.modify:/\",\"exp\":4102444800}",
                "ZHVtbXktc2lnbmF0dXJlLW5vdC12YWxpZA", fsig, sizeof(fsig)) == 0) {
            dx_authz_forged(a, u, "authz-forgesig", fsig, e);
        }
        if (dx_make_jwt(
                "{\"alg\":\"none\",\"typ\":\"JWT\"}",
                "{\"iss\":\"https://xrddiag.invalid\",\"sub\":\"xrddiag-probe\","
                "\"scope\":\"storage.read:/ storage.modify:/\",\"exp\":4102444800}",
                "", fnone, sizeof(fnone)) == 0) {
            dx_authz_forged(a, u, "authz-algnone", fnone, e);
        }
    } else {
        dx_record(e, "authz-token", DX_OK, 0,
                  "server does not offer bearer-token auth (forged-token tests N/A)", "");
    }

    /* 4,5) tests that require the operator's real token. */
    tok = xrdc_token_discover();
    if (tok != NULL) {
        xrdc_token_meta m;
        xrdc_token_meta_get(tok, &m);
        if (ztn_adv && m.valid && m.expired) {
            dx_authz_expired(a, u, tok, e);
        }
        if (a->allow_write && ztn_adv && m.valid && m.has_scope
            && m.has_read && !m.has_write
            && (dx_is_loopback(e->host) || a->authorized)) {
            dx_authz_scope(a, u, tok, e);
        }
        free(tok);
    }
}

/*
 * Run the active-diagnosis battery over an already-open connection. Read-only probes
 * always run; write/stage probes run only when --allow-write is set AND the target is
 * loopback or the operator passed --i-am-authorized (mutations on a remote server).
 */
static void
doctor_diagnose(const diag_args *a, xrdc_conn *c, const xrdc_url *u,
                const char *target, int have_target, doctor_ep *e)
{
    dx_probe_auth(c, e);
    dx_probe_namespace(c, e);
    if (have_target) {
        dx_probe_read(c, target, e);
        dx_probe_checksum(c, target, e);
    }
    {
        char        loc[2048];
        xrdc_status lst;
        xrdc_status_clear(&lst);
        if (xrdc_locate(c, u->path[0] ? u->path : "/", loc, sizeof(loc), &lst) != 0) {
            dx_record_status(e, "locate", &lst);
        } else {
            char *t, *save;
            for (t = strtok_r(loc, " \t\r\n", &save); t != NULL;
                 t = strtok_r(NULL, " \t\r\n", &save)) {
                if (t[0] == 'S') { e->holders++; }
            }
            if (e->holders == 0) {
                dx_record(e, "locate", DX_WARN, 0, "no replica located for the path",
                          "check data-server health and the CMS/manager registry");
            } else {
                dx_record(e, "locate", DX_OK, 0, "replica(s) located", "");
            }
        }
    }
    if (a->allow_write) {
        int permitted = dx_is_loopback(e->host) || a->authorized;
        if (!permitted) {
            dx_record(e, "write", DX_WARN, 0,
                      "write probe skipped on a non-loopback host without --i-am-authorized",
                      "re-run with --i-am-authorized to actively probe the write path");
        } else {
            dx_probe_write(c, e);
            if (have_target && e->offline_seen) {
                dx_probe_stage(c, target, e);
            }
        }
    }
    if (a->auth_suite) {
        doctor_auth_suite(a, u, target, have_target, e);
    }
}

/* ================================================================== */
/* multi-protocol deep-dive: http / https / davs / s3 / cms batteries  */
/* ================================================================== */

static const char *
dx_proto_name(dx_proto p)
{
    switch (p) {
    case DXP_HTTP:  return "http";
    case DXP_HTTPS: return "https";
    case DXP_DAVS:  return "davs";
    case DXP_S3:    return "s3";
    case DXP_CMS:   return "cms";
    default:        return "root";
    }
}

/*
 * Parse a scheme://host[:port][/path] URL for the deep-dive router. Recognizes
 * root[s]/xroot[s], http/https, dav/davs, s3/s3s, cms. Fills proto, *tls, host,
 * *port (a per-scheme default if absent), and path. Returns 0, or -1 if the scheme
 * is unknown. IPv6 literals in [..] are accepted.
 */
static int
dx_url_parse(const char *url, dx_proto *proto, int *tls, char *host, size_t hsz,
             int *port, char *path, size_t psz)
{
    const char *p = url, *hoststart, *slash;
    int         defport;

    *tls = 0;
    if      (strncmp(p, "roots://", 8) == 0)  { *proto = DXP_ROOT; *tls = 1; defport = 1094; p += 8; }
    else if (strncmp(p, "xroots://", 9) == 0) { *proto = DXP_ROOT; *tls = 1; defport = 1094; p += 9; }
    else if (strncmp(p, "root://", 7) == 0)   { *proto = DXP_ROOT; defport = 1094; p += 7; }
    else if (strncmp(p, "xroot://", 8) == 0)  { *proto = DXP_ROOT; defport = 1094; p += 8; }
    else if (strncmp(p, "https://", 8) == 0)  { *proto = DXP_HTTPS; *tls = 1; defport = 8443; p += 8; }
    else if (strncmp(p, "http://", 7) == 0)   { *proto = DXP_HTTP; defport = 8080; p += 7; }
    else if (strncmp(p, "davs://", 7) == 0)   { *proto = DXP_DAVS; *tls = 1; defport = 8443; p += 7; }
    else if (strncmp(p, "dav://", 6) == 0)    { *proto = DXP_DAVS; defport = 8080; p += 6; }
    else if (strncmp(p, "s3s://", 6) == 0)    { *proto = DXP_S3; *tls = 1; defport = 443; p += 6; }
    else if (strncmp(p, "s3://", 5) == 0)     { *proto = DXP_S3; defport = 9000; p += 5; }
    else if (strncmp(p, "cms://", 6) == 0)    { *proto = DXP_CMS; defport = 1213; p += 6; }
    else { return -1; }

    *port = defport;
    hoststart = p;
    if (*p == '[') {                            /* [IPv6] */
        const char *rb = strchr(p, ']');
        if (rb == NULL) { return -1; }
        {
            size_t n = (size_t) (rb - (p + 1));
            if (n == 0 || n >= hsz) { return -1; }
            memcpy(host, p + 1, n); host[n] = '\0';
        }
        p = rb + 1;
        if (*p == ':') { *port = atoi(p + 1); }
    } else {
        const char *colon = NULL, *e;
        for (e = hoststart; *e != '\0' && *e != '/'; e++) {
            if (*e == ':') { colon = e; }
        }
        {
            const char *hend = colon ? colon : e;
            size_t      n = (size_t) (hend - hoststart);
            if (n == 0 || n >= hsz) { return -1; }
            memcpy(host, hoststart, n); host[n] = '\0';
            if (colon != NULL) { *port = atoi(colon + 1); }
        }
    }
    if (*port <= 0 || *port > 65535) { return -1; }
    slash = strchr(p, '/');
    snprintf(path, psz, "%s", slash ? slash : "/");
    return 0;
}

/* Classify an HTTP status into an "http" finding on e. */
static void
dx_http_status(doctor_ep *e, const char *probe, int status)
{
    if (status >= 200 && status < 300) {
        dx_record(e, probe, DX_OK, status, "request succeeded", "");
    } else if (status == 401 || status == 403) {
        dx_record(e, probe, DX_WARN, status,
                  "access requires authentication/authorization (401/403)",
                  "provide a credential (Bearer token / cert) if this object should be reachable");
    } else if (status == 404 || status == 410) {
        dx_record(e, probe, DX_WARN, status, "object not found (404/410)",
                  "verify the path/bucket/key exists on the server");
    } else if (status >= 300 && status < 400) {
        dx_record(e, probe, DX_WARN, status, "server returned a redirect (3xx)",
                  "follow the Location target; check it is intended");
    } else if (status >= 500) {
        dx_record(e, probe, DX_FAIL, status, "server error (5xx) on the request",
                  "check the server logs for this operation");
    } else if (status == 0) {
        dx_record(e, probe, DX_FAIL, 0, "no HTTP status parsed (malformed/partial response)",
                  "the endpoint may not be an HTTP server on this port");
    } else {
        dx_record(e, probe, DX_WARN, status, "unexpected HTTP status", "");
    }
}

/* Classify an HTTP-family transport failure (connect / TLS) on e. */
static void
dx_http_fail(doctor_ep *e, int tls, const xrdc_status *st)
{
    const char *cause  = "connection setup failed";
    const char *remedy = "check the endpoint is up and the port is correct";
    if (tls && st->kxr == XRDC_EAUTH) {
        cause  = "TLS verification failed (cert untrusted/expired/wrong host)";
        remedy = "fix the server certificate chain, or pass --no-verify-tls for a self-signed test endpoint";
    } else if (st->sys_errno == ECONNREFUSED) {
        cause  = "no listener on host:port (service down or wrong port)";
        remedy = "start the gateway / verify the port and any firewall";
    } else if (st->sys_errno == ETIMEDOUT || st->sys_errno == EHOSTUNREACH
               || st->sys_errno == ENETUNREACH) {
        cause  = "host/network unreachable";
        remedy = "check routing/firewall and that the host is up";
    }
    doc_issue(e, DOC_RED, "%s", cause);
    dx_record(e, tls ? "tls" : "reachability", DX_FAIL, st->kxr, cause, remedy);
}

/*
 * http / https deep-dive: connect (+TLS cert/cipher), HEAD/GET the path, classify
 * the HTTP status, byte-range support, the Digest (checksum) header, and 401 auth
 * posture. For davs, also OPTIONS (WebDAV class) and PROPFIND (listing). Every probe
 * is bounded by the per-probe timeout. PII-free: only statuses/header-names/sizes.
 */
static void
doctor_http(const diag_args *a, dx_proto proto, int tls, const char *host,
            int port, const char *path, doctor_ep *e)
{
    xrdc_http_resp r;
    xrdc_status    st;
    int            verify = a->verify_tls;
    int            tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    char           val[512];

    memset(e, 0, sizeof(*e));
    e->proto = proto;
    e->status = DOC_GREEN;
    snprintf(e->host, sizeof(e->host), "%s", host);
    e->port = port;

    /* Stage 1: reachability + (TLS handshake/cert). Try HEAD; fall back to a 1-byte
     * ranged GET if HEAD is refused, so we still measure connect/TLS. */
    xrdc_status_clear(&st);
    if (xrdc_http_req(host, port, tls, "HEAD", path, NULL, NULL, 0, tmo, verify,
                      NULL, &r, &st) != 0) {
        xrdc_status_clear(&st);
        if (xrdc_http_req(host, port, tls, "GET", path, "Range: bytes=0-0\r\n",
                          NULL, 0, tmo, verify, NULL, &r, &st) != 0) {
            dx_http_fail(e, tls, &st);
            return;
        }
    }
    e->connected = 1;
    if (tls) {
        e->tls_active = 1;
        snprintf(e->tls_ver, sizeof(e->tls_ver), "%s", r.tls_ver);
        snprintf(e->tls_cipher, sizeof(e->tls_cipher), "%s", r.tls_cipher);
        dx_record(e, "tls", DX_OK, 0, "TLS handshake completed + certificate accepted", "");
    }

    /* Stage 2: HTTP status. */
    dx_http_status(e, "http", r.status);

    /* Stage 3: byte ranges (partial reads / multi-stream transfers depend on this). */
    if (xrdc_http_header(&r, "Accept-Ranges", val, sizeof(val))
        && strstr(val, "bytes") != NULL) {
        dx_record(e, "ranges", DX_OK, 0, "byte-range reads supported (Accept-Ranges: bytes)", "");
    } else {
        dx_record(e, "ranges", DX_WARN, 0,
                  "server did not advertise Accept-Ranges (partial/parallel reads may not work)",
                  "enable range support if clients use partial reads");
    }

    /* Stage 4: checksum advertisement (RFC-3230 Digest, WLCG transfers rely on it). */
    if (xrdc_http_header(&r, "Digest", val, sizeof(val)) && strchr(val, '=') != NULL) {
        /* RFC-3230 form is "algo=value"; require the '=' so a malformed header
         * isn't counted as a working checksum. */
        dx_record(e, "checksum", DX_OK, 0, "server advertises a content Digest (checksum)", "");
    } else {
        dx_record(e, "checksum", DX_WARN, 0,
                  "no Digest header (checksum verification unavailable over HTTP)",
                  "enable Want-Digest/Digest if integrity checks are required");
    }

    /* Stage 5: content-length present (sized transfers). */
    if (xrdc_http_header(&r, "Content-Length", val, sizeof(val))) {
        dx_record(e, "content-length", DX_OK, 0, "response is sized (Content-Length present)", "");
    }
    xrdc_http_resp_free(&r);

    /* davs extras: OPTIONS (WebDAV class) + PROPFIND (collection listing). */
    if (proto == DXP_DAVS) {
        xrdc_status_clear(&st);
        if (xrdc_http_req(host, port, tls, "OPTIONS", path, NULL, NULL, 0, tmo,
                          verify, NULL, &r, &st) == 0) {
            if (xrdc_http_header(&r, "DAV", val, sizeof(val))) {
                int class2 = (strstr(val, "2") != NULL);
                dx_record(e, "davs-class", DX_OK, r.status,
                          class2 ? "WebDAV class 2 advertised (LOCK supported)"
                                 : "WebDAV advertised (DAV header present)", "");
            } else {
                dx_record(e, "davs-class", DX_WARN, r.status,
                          "OPTIONS returned no DAV header (WebDAV may be disabled)",
                          "confirm xrootd_webdav is on for this location");
            }
            if (xrdc_http_header(&r, "Allow", val, sizeof(val))
                && strstr(val, "COPY") != NULL) {
                dx_record(e, "davs-tpc", DX_OK, 0,
                          "COPY method allowed (third-party-copy capable)", "");
            }
            xrdc_http_resp_free(&r);
        } else {
            dx_record(e, "davs-class", DX_WARN, st.kxr,
                      "OPTIONS request failed", "");
        }
        xrdc_status_clear(&st);
        if (xrdc_http_req(host, port, tls, "PROPFIND", path, "Depth: 1\r\n",
                          NULL, 0, tmo, verify, NULL, &r, &st) == 0) {
            if (r.status == 207) {
                dx_record(e, "davs-listing", DX_OK, 207,
                          "PROPFIND multistatus listing works", "");
            } else if (r.status == 401 || r.status == 403) {
                dx_record(e, "davs-listing", DX_WARN, r.status,
                          "PROPFIND requires authentication", "provide a credential");
            } else {
                dx_record(e, "davs-listing", DX_WARN, r.status,
                          "PROPFIND did not return 207 multistatus", "");
            }
            xrdc_http_resp_free(&r);
        }
    }
}

/* ---------------- S3 (SigV4) ---------------- */

/* Build an AWS SigV4 Authorization header block (path-style URI) via the shared
 * lib signer (lib/s3.c) so xrddiag and xrdcp sign identically. UNSIGNED-PAYLOAD is
 * used as the body hash — accepted by nginx-xrootd's S3 and by real AWS. 0/-1. */
static int
s3_sign(const char *method, const char *host, const char *uri,
        const char *ak, const char *sk, const char *region,
        char *hdrs, size_t hdrsz)
{
    return xrdc_s3_sign_v4(method, host, uri, ak, sk, region,
                           "UNSIGNED-PAYLOAD", hdrs, hdrsz);
}

/*
 * s3 deep-dive: connect (+TLS), an UNAUTHENTICATED GET to confirm reachability +
 * that the server enforces auth (403/AccessDenied) vs is public (200) vs missing
 * (404/NoSuchBucket). If AWS_ACCESS_KEY_ID/SECRET are in the environment, also send
 * a SigV4-signed HEAD and confirm the signature is accepted (catches signer/clock/
 * region faults). PII-free: never emits the key or signature.
 */
static void
doctor_s3(const diag_args *a, int tls, const char *host, int port,
          const char *uri, doctor_ep *e)
{
    xrdc_http_resp r;
    xrdc_status    st;
    int            verify = a->verify_tls;
    int            tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    const char    *ak = getenv("AWS_ACCESS_KEY_ID");
    const char    *sk = getenv("AWS_SECRET_ACCESS_KEY");

    memset(e, 0, sizeof(*e));
    e->proto = DXP_S3;
    e->status = DOC_GREEN;
    snprintf(e->host, sizeof(e->host), "%s", host);
    e->port = port;

    /* Stage 1: reachability + TLS via an unauthenticated GET. */
    xrdc_status_clear(&st);
    if (xrdc_http_req(host, port, tls, "GET", uri, NULL, NULL, 0, tmo, verify,
                      NULL, &r, &st) != 0) {
        dx_http_fail(e, tls, &st);
        return;
    }
    e->connected = 1;
    if (tls) {
        e->tls_active = 1;
        snprintf(e->tls_ver, sizeof(e->tls_ver), "%s", r.tls_ver);
        snprintf(e->tls_cipher, sizeof(e->tls_cipher), "%s", r.tls_cipher);
        dx_record(e, "tls", DX_OK, 0, "TLS handshake completed + certificate accepted", "");
    }
    if (r.status == 403) {
        dx_record(e, "s3-auth", DX_OK, 403,
                  "endpoint enforces S3 authentication (anonymous request denied)", "");
    } else if (r.status == 404) {
        dx_record(e, "s3-bucket", DX_WARN, 404,
                  "bucket/key not found (NoSuchBucket/NoSuchKey)",
                  "verify the bucket and key path");
    } else if (r.status >= 200 && r.status < 300) {
        dx_record(e, "s3-auth", DX_WARN, r.status,
                  "anonymous S3 request SUCCEEDED — the resource is public",
                  "confirm public access is intended; otherwise restrict it");
    } else {
        dx_http_status(e, "s3-req", r.status);
    }
    xrdc_http_resp_free(&r);

    /* Stage 2: authenticated SigV4 probe (only if AWS creds are present). */
    if (ak != NULL && sk != NULL && ak[0] != '\0' && sk[0] != '\0') {
        char        hdrs[1024];
        char        hostport[300];
        const char *region = getenv("AWS_DEFAULT_REGION");
        if (region == NULL || region[0] == '\0') { region = "us-east-1"; }
        /* Sign the exact Host header we send (host:port) — the server canonicalises
         * the Host value verbatim, so signing the bare host would mismatch. */
        snprintf(hostport, sizeof(hostport), "%s:%d", host, port);
        if (s3_sign("GET", hostport, uri, ak, sk, region, hdrs, sizeof(hdrs)) != 0) {
            dx_record(e, "s3-sigv4", DX_WARN, 0, "could not build a SigV4 signature (client)", "");
        } else {
            xrdc_status_clear(&st);
            if (xrdc_http_req(host, port, tls, "GET", uri, hdrs, NULL, 0, tmo,
                              verify, NULL, &r, &st) != 0) {
                dx_record(e, "s3-sigv4", DX_WARN, st.kxr, "signed request failed to complete", "");
            } else {
                if (r.status >= 200 && r.status < 300) {
                    dx_record(e, "s3-sigv4", DX_OK, r.status,
                              "SigV4-signed request accepted (signature/clock/region OK)", "");
                } else if (r.status == 403) {
                    /* read the S3 <Code> element (not a body-wide substring, which
                     * could false-match) to tell a signature fault from a policy deny. */
                    const char *cs = r.body ? strstr(r.body, "<Code>") : NULL;
                    int sig_fault = (cs != NULL
                                     && strncmp(cs + 6, "SignatureDoesNotMatch", 21) == 0);
                    if (sig_fault) {
                        dx_record(e, "s3-sigv4", DX_FAIL, 403,
                                  "SigV4 signature rejected (SignatureDoesNotMatch — clock skew / region / key mismatch)",
                                  "check client clock vs server, the region, and the access key/secret");
                    } else {
                        dx_record(e, "s3-sigv4", DX_WARN, 403,
                                  "signed request denied (access policy, not a signature fault)",
                                  "check the bucket/object policy for this identity");
                    }
                } else {
                    dx_http_status(e, "s3-sigv4", r.status);
                }
                xrdc_http_resp_free(&r);
            }
        }
    } else {
        dx_record(e, "s3-sigv4", DX_OK, 0,
                  "no AWS credentials in environment — signed-request check skipped (posture only)",
                  "set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY to test SigV4 acceptance");
    }
}

/*
 * cms deep-dive: a cluster manager (cmsd/redirector) is a root:// endpoint that
 * answers kXR_locate with the data server(s) holding a path and issues kXR_redirect.
 * Connect to the manager, locate the path, and confirm the redirect resolution to a
 * reachable data server; flag no-holder / unreachable-DS (ghost) / redirect issues.
 * Reuses the libxrdc locate + reconnect machinery (the redirect loop-guard applies).
 */
static void
doctor_cms(const diag_args *a, const char *host, int port, const char *path,
           doctor_ep *e)
{
    xrdc_url    u;
    xrdc_conn   c;
    xrdc_status st;

    memset(e, 0, sizeof(*e));
    e->proto = DXP_CMS;
    e->status = DOC_GREEN;
    snprintf(e->host, sizeof(e->host), "%s", host);
    e->port = port;

    memset(&u, 0, sizeof(u));
    u.scheme = XRDC_SCHEME_ROOT;
    snprintf(u.host, sizeof(u.host), "%s", host);
    u.port = port;
    snprintf(u.path, sizeof(u.path), "%s", path[0] ? path : "/");

    xrdc_status_clear(&st);
    if (xrdc_connect(&c, &u, &a->conn, &st) != 0) {
        dx_record(e, "cms-connect", DX_FAIL, st.kxr,
                  "could not connect to the cluster manager",
                  "check the manager (cmsd/redirector) is up on this host:port");
        doc_issue(e, DOC_RED, "manager connect failed");
        return;
    }
    e->connected = 1;
    c.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;
    dx_record(e, "cms-connect", DX_OK, 0, "manager reachable + login completed", "");

    {
        char        loc[2048];
        xrdc_status lst;
        xrdc_status_clear(&lst);
        if (xrdc_locate(&c, u.path, loc, sizeof(loc), &lst) != 0) {
            /* a manager returns NotFound when no server holds the path. */
            dx_record_status(e, "cms-locate", &lst);
        } else {
            char *t, *save;
            for (t = strtok_r(loc, " \t\r\n", &save); t != NULL;
                 t = strtok_r(NULL, " \t\r\n", &save)) {
                if (t[0] == 'S') { e->holders++; }
            }
            if (e->holders == 0) {
                dx_record(e, "cms-locate", DX_FAIL, 0,
                          "manager located no data server for the path (no holder)",
                          "check data-server registration and the CMS registry");
            } else {
                dx_record(e, "cms-locate", DX_OK, 0,
                          "manager resolved the path to data server(s)", "");
            }
        }
    }

    /* Resolution: a stat through the manager must follow the redirect to a live DS.
     * A redirect loop or dead DS surfaces here (the loop-guard returns an error). */
    {
        xrdc_statinfo si;
        xrdc_status   rst;
        xrdc_status_clear(&rst);
        if (xrdc_stat(&c, u.path, &si, &rst) == 0) {
            dx_record(e, "cms-redirect", DX_OK, 0,
                      "manager→data-server redirect resolved to a live server", "");
        } else if (rst.kxr == kXR_NotFound) {
            dx_record(e, "cms-redirect", DX_WARN, rst.kxr,
                      "path not found via the manager (redirect resolved, file absent)",
                      "verify the path exists on a registered data server");
        } else {
            dx_record(e, "cms-redirect", DX_FAIL, rst.kxr,
                      "manager redirect did not resolve to a reachable data server (dead DS / redirect loop)",
                      "check data-server health and the CMS registry for stale entries");
        }
    }
    xrdc_close(&c);
}

/* Interrogate ONE endpoint into *e. Bounded by the conn timeout (never hangs). */
static void
doctor_one(const diag_args *a, const char *url, doctor_ep *e)
{
    xrdc_url      u;
    xrdc_conn     c;
    xrdc_status   st;
    const char   *ver = NULL, *cipher = NULL;
    char          target[XRDC_PATH_MAX];
    int           have_target = 0;

    target[0] = '\0';
    memset(e, 0, sizeof(*e));
    e->status = DOC_GREEN;
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(url, &u, &st) != 0) {
        snprintf(e->host, sizeof(e->host), "%s", url);
        doc_issue(e, DOC_RED, "unparseable URL (bad scheme/host/port)");
        return;
    }
    snprintf(e->host, sizeof(e->host), "%s", u.host);
    e->port = u.port;

    if (xrdc_connect(&c, &u, &a->conn, &st) != 0) {
        /* Distinguish "server reachable but auth failed" from "couldn't reach it"
         * by the client's error CODE: XRDC_EAUTH / kXR_NotAuthorized / kXR_AuthFailed
         * mean auth was attempted and rejected; everything else is transport. */
        if (st.kxr == XRDC_EAUTH || st.kxr == kXR_NotAuthorized
            || st.kxr == kXR_AuthFailed) {
            doc_issue(e, DOC_RED, "authentication failed");
            dx_record(e, "auth", DX_FAIL, st.kxr,
                      "could not authenticate (credential rejected, or none usable for the server's auth)",
                      "check the credential's validity/scope and that it matches the server's auth mode");
        } else {
            /* reachability: classify *why* the connection could not be set up. */
            const char *cause = "connection setup failed";
            const char *remedy = "check the network path and that the server is running";
            if (st.sys_errno == ECONNREFUSED) {
                cause  = "no listener on host:port (service down or wrong port)";
                remedy = "start the gateway / verify the port and any firewall";
            } else if (st.sys_errno == ETIMEDOUT || st.sys_errno == EHOSTUNREACH
                       || st.sys_errno == ENETUNREACH) {
                cause  = "host/network unreachable (routing or firewall drop)";
                remedy = "check routing/firewall and that the host is up";
            } else if (st.msg[0] != '\0' && strstr(st.msg, "resolve") != NULL) {
                cause  = "DNS resolution failed";
                remedy = "check the hostname and DNS resolver";
            }
            /* use the classified cause, not st.msg — wire text may carry PII. */
            doc_issue(e, DOC_RED, "connect failed: %s", cause);
            dx_record(e, "reachability", DX_FAIL, st.kxr, cause, remedy);
        }
        /* the auth-suite is self-contained (its own force_anon session) — run it
         * even when our credential could not establish the primary connection. */
        if (a->auth_suite) {
            doctor_auth_suite(a, &u, target, 0, e);
        }
        return;
    }
    e->connected = 1;
    c.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;

    /* network + transport facts */
    xrdc_netdiag_facts(&c, &e->nf);
    e->caps = (unsigned) c.server_flags;
    e->gototls = (c.server_flags & kXR_gotoTLS) != 0;
    e->tls_active = xrdc_tls_info(&c, &ver, &cipher);
    if (e->tls_active) {
        snprintf(e->tls_ver, sizeof(e->tls_ver), "%s", ver ? ver : "?");
        snprintf(e->tls_cipher, sizeof(e->tls_cipher), "%s", cipher ? cipher : "?");
    }
    snprintf(e->auth, sizeof(e->auth), "%s",
             c.diag.chosen_auth ? c.diag.chosen_auth : "anon");

    /* no-silent-downgrade: gotoTLS advertised but the session is cleartext */
    if (e->gototls && !e->tls_active) {
        doc_issue(e, DOC_RED, "gotoTLS advertised but session is cleartext");
    }

    /* throughput probe over a resolved file (skip cleanly if the export is empty) */
    {
        xrdc_statinfo sti;
        xrdc_status   rst;
        xrdc_status_clear(&rst);
        if (resolve_target(&c, &u, target, sizeof(target), &sti, &rst) == 0) {
            have_target = 1;
            if (doctor_xfer(&c, target, &e->ttfb_ms, &e->mbps, &e->xfer_bytes)
                == 0) {
                e->have_xfer = 1;
            }
        }
    }

    /* active differential diagnosis — exercise subsystems + classify (incl. locate). */
    doctor_diagnose(a, &c, &u, target, have_target, e);

    xrdc_close(&c);

    /* server-side load signal (cleartext /metrics; best-effort, 0 = skip) */
    if (a->metrics_port > 0) {
        doctor_metrics(e->host, a->metrics_port, e);
    }
    if (e->shedding) {
        doc_issue(e, DOC_YELLOW, "server reports kXR_wait / budget shedding");
    }
    /* cwnd/BDP signal — only meaningful once enough bytes moved to time it. */
    if (e->have_xfer && e->xfer_bytes >= (4 << 20) && e->nf.have_tcpinfo
        && e->nf.rtt_us > 0 && e->nf.rtt_us < 5000 && e->mbps < 5.0) {
        doc_issue(e, DOC_YELLOW, "low throughput (%.1f MB/s) at low RTT — cwnd/BDP?",
                  e->mbps);
    }
    if (e->nf.have_tcpinfo && e->nf.retrans > 0) {
        doc_issue(e, DOC_YELLOW, "%u TCP retransmit(s)", e->nf.retrans);
    }
}

static const char *
doc_color(int s)
{
    return s == DOC_RED ? "RED" : s == DOC_YELLOW ? "YELLOW" : "GREEN";
}

/* Cross-endpoint diff engine over the transfer path. Returns #critical diffs. */
static int
doctor_cross(const doctor_ep *eps, int n, FILE *out)
{
    int i, crit = 0, connected = 0;
    if (n < 2) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (eps[i].connected) { connected++; }
    }
    if (connected < 2) {
        return 0;   /* fewer than two reachable hops — nothing to compare */
    }
    fprintf(out, "Path analysis (%d hops):\n", n);
    for (i = 1; i < n; i++) {
        const doctor_ep *p = &eps[i - 1], *q = &eps[i];
        if (!p->connected || !q->connected) {
            continue;
        }
        /* TLS-downgrade: a TLS hop followed by a cleartext one */
        if (p->tls_active && !q->tls_active) {
            fprintf(out, "  %s:%d -> %s:%d  TLS DOWNGRADE (encrypted then cleartext)\n",
                    p->host, p->port, q->host, q->port);
            crit++;
        }
        /* auth-fallback: the chosen auth weakens across the hop */
        if (strcmp(p->auth, q->auth) != 0) {
            fprintf(out, "  %s:%d -> %s:%d  auth changed %s -> %s\n",
                    p->host, p->port, q->host, q->port, p->auth, q->auth);
        }
        /* v4/v6 asymmetry */
        if (p->nf.family && q->nf.family && p->nf.family != q->nf.family) {
            fprintf(out, "  %s:%d -> %s:%d  address-family asymmetry (%s vs %s)\n",
                    p->host, p->port, q->host, q->port,
                    p->nf.family == 10 ? "IPv6" : "IPv4",
                    q->nf.family == 10 ? "IPv6" : "IPv4");
        }
    }
    return crit;
}

/* Write a JSON-escaped, double-quoted string — strings may carry server-supplied
 * wire text (st->msg), so control bytes / quotes / backslashes must be escaped. */
static void
fjson_str(FILE *out, const char *s)
{
    fputc('"', out);
    for (; s != NULL && *s != '\0'; s++) {
        unsigned char ch = (unsigned char) *s;
        switch (ch) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out);  break;
        case '\r': fputs("\\r", out);  break;
        case '\t': fputs("\\t", out);  break;
        default:
            /* escape control AND high bytes so the output is always valid JSON,
             * even if a server returned non-ASCII wire text. */
            if (ch < 0x20 || ch >= 0x80) { fprintf(out, "\\u%04x", ch); }
            else                         { fputc((int) ch, out); }
        }
    }
    fputc('"', out);
}

static const char *
dx_verdict_name(int v)
{
    return v == DX_FAIL ? "fail" : v == DX_WARN ? "warn" : "ok";
}

static void
doctor_emit_json(const doctor_ep *eps, int n, FILE *out)
{
    int i, j;
    fprintf(out, "{\"remote_doctor\":{\"endpoints\":[");
    for (i = 0; i < n; i++) {
        const doctor_ep *e = &eps[i];
        fprintf(out, "%s{\"protocol\":\"%s\",\"host\":", i ? "," : "",
                dx_proto_name(e->proto));
        fjson_str(out, e->host);
        fprintf(out, ",\"port\":%d,\"status\":\"%s\","
                "\"connected\":%s,\"facts\":{\"family\":\"%s\","
                "\"tcp_ms\":%.3f,\"tls_ms\":%.3f,\"auth_ms\":%.3f,\"total_ms\":%.3f,"
                "\"rtt_us\":%u,\"retrans\":%u,\"tls\":\"%s\",\"auth\":\"%s\","
                "\"caps\":\"0x%x\",\"ttfb_ms\":%.3f,\"mbps\":%.1f,\"holders\":%d,"
                "\"metrics_http\":%d,\"shedding\":%s},\"issues\":[",
                e->port, doc_color(e->status),
                e->connected ? "true" : "false",
                e->nf.family == 10 ? "IPv6" : e->nf.family == 2 ? "IPv4" : "none",
                e->nf.tcp_ms, e->nf.tls_ms, e->nf.auth_ms, e->nf.total_ms,
                e->nf.rtt_us, e->nf.retrans,
                e->tls_active ? e->tls_ver : "none", e->auth, e->caps,
                e->ttfb_ms, e->mbps, e->holders, e->metrics_http,
                e->shedding ? "true" : "false");
        for (j = 0; j < e->nissues; j++) {
            if (j) { fputc(',', out); }
            fjson_str(out, e->issues[j]);
        }
        fprintf(out, "],\"diagnosis\":[");
        for (j = 0; j < e->ndx; j++) {
            const dx_finding *d = &e->dx[j];
            fprintf(out, "%s{\"probe\":", j ? "," : "");
            fjson_str(out, d->probe);
            fprintf(out, ",\"verdict\":\"%s\",\"kxr\":%d,\"cause\":",
                    dx_verdict_name(d->verdict), d->kxr);
            fjson_str(out, d->cause);
            fprintf(out, ",\"remedy\":");
            fjson_str(out, d->remedy);
            fputc('}', out);
        }
        fprintf(out, "]}");
    }
    fprintf(out, "],\"cross_endpoint_analysis\":{\"hops\":%d}}}\n", n > 1 ? n - 1 : 0);
}

/* Human-readable diagnosis block for one endpoint: each probe's verdict, and for
 * problems the classified cause + remediation. */
static void
doctor_print_diagnosis(const doctor_ep *e)
{
    int j;
    if (e->ndx == 0) {
        return;
    }
    printf("  diagnosis:\n");
    for (j = 0; j < e->ndx; j++) {
        const dx_finding *d = &e->dx[j];
        const char       *tag = d->verdict == DX_FAIL ? "FAIL"
                              : d->verdict == DX_WARN ? "WARN" : "ok";
        printf("    [%-4s] %-11s %s\n", tag, d->probe, d->cause);
        if (d->verdict != DX_OK && d->remedy[0] != '\0') {
            printf("           → %s\n", d->remedy);
        }
    }
}

/* ------------------------------------------------------------------ */
/* srr + tape — HTTP/JSON consumers over the general HTTP client        */
/* ------------------------------------------------------------------ */

/* Scalar JSON scan (flat fields; no nesting awareness — sufficient for the SRR /
 * Tape-REST documents). Extract the string value of "key":"value" into out. 1/0. */
static int
js_str(const char *json, const char *key, char *out, size_t osz)
{
    char        pat[64];
    const char *p, *v, *e;
    if (json == NULL) { return 0; }
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(json, pat);
    if (p == NULL) { return 0; }
    p = strchr(p + strlen(pat), ':');
    if (p == NULL) { return 0; }
    p++;
    while (*p == ' ' || *p == '\t') { p++; }
    if (*p != '"') { return 0; }
    v = p + 1;
    /* Find the closing quote, honouring backslash escapes: a '"' preceded by an
     * even number of backslashes is the delimiter; an odd number means it's \". */
    e = v;
    while (*e != '\0') {
        if (*e == '"') {
            const char *bs = e;
            int         nb = 0;
            while (bs > v && bs[-1] == '\\') { nb++; bs--; }
            if ((nb & 1) == 0) { break; }
        }
        e++;
    }
    if (*e != '"') { return 0; }
    {
        size_t n = (size_t) (e - v);
        if (n >= osz) { n = osz - 1; }
        memcpy(out, v, n);
        out[n] = '\0';
    }
    return 1;
}

/* Sum every numeric "key": N occurrence in the document (e.g. all shares' sizes). */
static long long
js_sum(const char *json, const char *key)
{
    char        pat[64];
    const char *p;
    long long   sum = 0;
    if (json == NULL) { return 0; }
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *c = strchr(p + strlen(pat), ':');
        p += strlen(pat);
        if (c != NULL) {
            const char *n = c + 1;
            long long   v;
            while (*n == ' ' || *n == '\t') { n++; }
            v = strtoll(n, NULL, 10);
            /* saturating add — a diagnostic total must never wrap to nonsense. */
            if (v > 0 && sum > LLONG_MAX - v)      { sum = LLONG_MAX; }
            else if (v < 0 && sum < LLONG_MIN - v) { sum = LLONG_MIN; }
            else                                   { sum += v; }
        }
    }
    return sum;
}

/* Count occurrences of a key (e.g. number of storage shares). */
static int
js_count(const char *json, const char *key)
{
    char        pat[64];
    const char *p;
    int         n = 0;
    if (json == NULL) { return 0; }
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = json;
    while ((p = strstr(p, pat)) != NULL) { n++; p += strlen(pat); }
    return n;
}

/* xrddiag srr <http[s]-url> — fetch the WLCG Storage Resource Reporting document
 * and summarize the site's shares + capacity. Closes the SRR client gap. */
static int
do_srr(const diag_args *a)
{
    dx_proto       proto;
    int            tls, port;
    char           host[256], path[XRDC_PATH_MAX], name[128];
    xrdc_http_resp r;
    xrdc_status    st;
    int            tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;

    if (dx_url_parse(a->url, &proto, &tls, host, sizeof(host), &port, path,
                     sizeof(path)) != 0 || proto == DXP_ROOT) {
        fprintf(stderr, "xrddiag: srr needs an http(s):// URL\n");
        return 50;
    }
    if (path[0] == '\0' || strcmp(path, "/") == 0) {
        snprintf(path, sizeof(path), "/.well-known/wlcg-storage-resource-reporting");
    }
    xrdc_status_clear(&st);
    if (xrdc_http_req(host, port, tls, "GET", path, NULL, NULL, 0, tmo,
                      a->verify_tls, NULL, &r, &st) != 0) {
        fprintf(stderr, "xrddiag: srr GET %s:%d%s: %s\n", host, port, path, st.msg);
        return 51;
    }
    if (r.status != 200) {
        fprintf(stderr, "xrddiag: srr returned HTTP %d\n", r.status);
        xrdc_http_resp_free(&r);
        return 51;
    }
    if (a->json) {
        fwrite(r.body, 1, r.body_len, stdout);
    } else {
        long long total = js_sum(r.body, "totalsize");
        long long used  = js_sum(r.body, "usedsize");
        int       shares = js_count(r.body, "totalsize");
        if (js_str(r.body, "implementation", name, sizeof(name))) {
            printf("SRR: implementation=%s", name);
            if (js_str(r.body, "implementationversion", name, sizeof(name))) {
                printf(" %s", name);
            }
            printf("\n");
        }
        printf("  shares:   %d\n", shares);
        printf("  capacity: %lld bytes total, %lld used (%.1f%% full)\n",
               total, used, total > 0 ? 100.0 * (double) used / (double) total : 0.0);
    }
    xrdc_http_resp_free(&r);
    return 0;
}

/* xrddiag tape <http[s]-url//path> — drive the WLCG/FRM Tape REST API: POST a stage
 * request for the path, then poll its status once and report locality. Closes the
 * FRM Tape-REST client gap. */
static int
do_tape(const diag_args *a)
{
    dx_proto       proto;
    int            tls, port;
    char           host[256], path[XRDC_PATH_MAX], body[1024], reqid[128], state[32];
    xrdc_http_resp r;
    xrdc_status    st;
    int            tmo = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;

    if (dx_url_parse(a->url, &proto, &tls, host, sizeof(host), &port, path,
                     sizeof(path)) != 0 || proto == DXP_ROOT || path[0] != '/'
        || path[1] == '\0') {
        fprintf(stderr, "xrddiag: tape needs an http(s):// URL with a file path\n");
        return 50;
    }
    /* POST /api/v1/stage {"files":[{"path":"<path>"}]} — reject (don't silently
     * truncate) an over-long path, which would stage the wrong file. */
    if (strlen(path) > 900) {
        fprintf(stderr, "xrddiag: tape path too long (max 900 bytes)\n");
        return 50;
    }
    snprintf(body, sizeof(body), "{\"files\":[{\"path\":\"%s\"}]}", path);
    xrdc_status_clear(&st);
    if (xrdc_http_req(host, port, tls, "POST", "/api/v1/stage",
                      "Content-Type: application/json\r\n", body, strlen(body),
                      tmo, a->verify_tls, NULL, &r, &st) != 0) {
        fprintf(stderr, "xrddiag: tape stage POST: %s\n", st.msg);
        return 51;
    }
    if (r.status != 200 && r.status != 201) {
        fprintf(stderr, "xrddiag: tape stage returned HTTP %d\n", r.status);
        xrdc_http_resp_free(&r);
        return 51;
    }
    if (!js_str(r.body, "id", reqid, sizeof(reqid))
        && !js_str(r.body, "requestId", reqid, sizeof(reqid))) {
        fprintf(stderr, "xrddiag: tape stage: no request id in response\n");
        xrdc_http_resp_free(&r);
        return 51;
    }
    state[0] = '\0';
    (void) js_str(r.body, "state", state, sizeof(state));
    printf("stage accepted: request-id=%s state=%s\n", reqid, state[0] ? state : "?");
    xrdc_http_resp_free(&r);

    /* poll GET /api/v1/stage/{id} once. */
    {
        char poll[256];
        snprintf(poll, sizeof(poll), "/api/v1/stage/%s", reqid);
        xrdc_status_clear(&st);
        if (xrdc_http_req(host, port, tls, "GET", poll, NULL, NULL, 0, tmo,
                          a->verify_tls, NULL, &r, &st) == 0) {
            if (r.status == 200) {
                char ondisk[16];
                state[0] = '\0';
                (void) js_str(r.body, "state", state, sizeof(state));
                ondisk[0] = '\0';
                (void) js_str(r.body, "onDisk", ondisk, sizeof(ondisk));
                printf("poll: state=%s onDisk=%s\n", state[0] ? state : "?",
                       ondisk[0] ? ondisk : "?");
            }
            xrdc_http_resp_free(&r);   /* free on every successful request */
        }
    }
    return 0;
}

/* Route one URL to its protocol battery by scheme. root:// (and any unrecognized
 * scheme, for back-compat) goes to the full libxrdc battery; the rest to their
 * deep-dive batteries. */
static void
doctor_dispatch(const diag_args *a, const char *url, doctor_ep *e)
{
    dx_proto proto;
    int      tls, port;
    char     host[256], path[XRDC_PATH_MAX];

    if (dx_url_parse(url, &proto, &tls, host, sizeof(host), &port, path,
                     sizeof(path)) != 0 || proto == DXP_ROOT) {
        doctor_one(a, url, e);
        return;
    }
    switch (proto) {
    case DXP_HTTP:  doctor_http(a, DXP_HTTP, 0, host, port, path, e); break;
    case DXP_HTTPS: doctor_http(a, DXP_HTTPS, 1, host, port, path, e); break;
    case DXP_DAVS:  doctor_http(a, DXP_DAVS, tls, host, port, path, e); break;
    case DXP_S3:    doctor_s3(a, tls, host, port, path, e); break;
    case DXP_CMS:   doctor_cms(a, host, port, path, e); break;
    default:        doctor_one(a, url, e); break;
    }
}

static int
do_remote_doctor(const diag_args *a)
{
    doctor_ep eps[8];
    int       i, worst = DOC_GREEN, crit;

    if (a->nurls < 1) {
        fprintf(stderr, "xrddiag: remote-doctor needs at least one URL\n");
        return 50;
    }
    for (i = 0; i < a->nurls; i++) {
        doctor_dispatch(a, a->urls[i], &eps[i]);
        if (eps[i].status > worst) {
            worst = eps[i].status;
        }
    }

    if (a->json) {
        doctor_emit_json(eps, a->nurls, stdout);
        return (worst == DOC_RED) ? 1 : 0;
    }

    printf("remote-doctor: %d endpoint(s)\n", a->nurls);
    for (i = 0; i < a->nurls; i++) {
        const doctor_ep *e = &eps[i];
        int              j;
        printf("\n[%s] %s %s:%d\n", doc_color(e->status), dx_proto_name(e->proto),
               e->host, e->port);
        if (!e->connected) {
            for (j = 0; j < e->nissues; j++) { printf("  - %s\n", e->issues[j]); }
            doctor_print_diagnosis(e);
            continue;
        }
        /* root/cms use the libxrdc connection → full connect-phase + transport facts;
         * the HTTP-family batteries report TLS facts inline + the diagnosis block. */
        if (e->proto == DXP_ROOT) {
            printf("  connect: tcp %.1f / tls %.1f / login+auth %.1f ms  (%s)\n",
                   e->nf.tcp_ms, e->nf.tls_ms, e->nf.auth_ms,
                   e->nf.family == 10 ? "IPv6" : e->nf.family == 2 ? "IPv4" : "?");
            printf("  auth=%s  tls=%s%s%s  caps=0x%x\n", e->auth,
                   e->tls_active ? e->tls_ver : "none",
                   e->tls_active ? " " : "", e->tls_active ? e->tls_cipher : "",
                   e->caps);
            if (e->nf.have_tcpinfo) {
                printf("  tcp: rtt=%u us retrans=%u\n", e->nf.rtt_us, e->nf.retrans);
            }
            if (e->have_xfer) {
                printf("  xfer: ttfb %.1f ms, %.1f MB/s\n", e->ttfb_ms, e->mbps);
            }
            printf("  holders=%d  metrics=%s%s\n", e->holders,
                   e->metrics_http == 200 ? "reachable" : "n/a",
                   e->shedding ? " (SHEDDING)" : "");
        } else if (e->tls_active) {
            printf("  tls=%s %s\n", e->tls_ver, e->tls_cipher);
        }
        for (j = 0; j < e->nissues; j++) { printf("  - %s\n", e->issues[j]); }
        doctor_print_diagnosis(e);
    }

    /* client-side credential validity (the same creds reach every hop). */
    {
        char       *tok = xrdc_token_discover();
        const char *proxy = getenv("X509_USER_PROXY");
        if (tok != NULL || (proxy != NULL && proxy[0] != '\0')) {
            printf("\nCredentials (in environment):\n");
            if (tok != NULL) { xrdc_token_explain(tok, stdout); free(tok); }
            if (proxy != NULL && proxy[0] != '\0') {
                xrdc_gsi_cert_explain(proxy, stdout);
            }
        }
    }

    printf("\n");
    crit = doctor_cross(eps, a->nurls, stdout);
    printf("Result: worst=%s, %d critical path issue(s)\n", doc_color(worst), crit);
    return (worst == DOC_RED || crit > 0) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* watch — continuous health / SLA probe loop                          */
/* ------------------------------------------------------------------ */

/* One probe result for one endpoint. PII-free: timings + counts only; the only
 * label is the endpoint the user passed (host:port), never a resolved IP/path. */
typedef struct {
    int         up;                 /* 1 = connected, 0 = down/unreachable */
    double      connect_ms;         /* full connect (TCP+TLS+login+auth) */
    double      tcp_ms, tls_ms, auth_ms;  /* connect-phase split (netfacts) */
    double      read_ms;            /* tiny-read TTFB, -1 if not measured */
    double      locate_ms;          /* kXR_locate RTT, -1 if not measured */
    int         holders;            /* located replica count, -1 if unknown */
    int         tls_active;         /* 1 if the data plane negotiated TLS */
    const char *proto;              /* "root" / "roots" */
    char        endpoint[288];      /* the URL the user passed */
} watch_sample;

/* Set only by the signal handler; the loop polls it and stops cleanly. */
static volatile sig_atomic_t g_watch_stop;

static void
watch_on_signal(int sig)
{
    (void) sig;
    g_watch_stop = 1;   /* async-signal-safe: a flag set is all we do */
}

/* Count whitespace/comma-separated tokens (≈ located replica hosts). We only ever
 * emit the COUNT, never the locate buffer, so no host/IP leaks. */
static int
watch_count_tokens(const char *s)
{
    int n = 0, in = 0;
    for (; *s != '\0'; s++) {
        int delim = (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n' || *s == ',');
        if (!delim && !in) { in = 1; n++; }
        else if (delim)    { in = 0; }
    }
    return n;
}

/* Escape a Prometheus label value: backslash/quote/newline per the exposition
 * format; any other control byte (\r, \t, …) is dropped so the output is always a
 * single valid line (endpoint labels are host:port, so this is just defensive). */
static void
watch_prom_label(const char *s, char *out, size_t osz)
{
    size_t j = 0;
    for (; *s != '\0' && j + 2 < osz; s++) {
        unsigned char ch = (unsigned char) *s;
        if (ch == '\\' || ch == '"') { out[j++] = '\\'; out[j++] = (char) ch; }
        else if (ch == '\n')         { out[j++] = '\\'; out[j++] = 'n'; }
        else if (ch < 0x20)          { continue; }   /* drop \r/\t/other controls */
        else                         { out[j++] = (char) ch; }
    }
    out[j] = '\0';
}

/* Probe one endpoint once: connect (timed), connect-phase split, a tiny read
 * (TTFB), and a locate (replica count). Never aborts the loop — a down endpoint
 * just yields up=0. Always returns 0. */
static int
watch_probe_once(const diag_args *a, const char *url, watch_sample *out)
{
    xrdc_url      u;
    xrdc_conn     c;
    xrdc_status   st;
    xrdc_netfacts f;
    char          target[XRDC_PATH_MAX];
    xrdc_statinfo sti;
    uint64_t      t0;

    memset(out, 0, sizeof(*out));
    snprintf(out->endpoint, sizeof(out->endpoint), "%s", url);
    out->read_ms = out->locate_ms = -1.0;
    out->holders = -1;
    out->proto = "root";

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(url, &u, &st) != 0) {
        /* PII-free contract: never let a raw URL's path/query reach a label. */
        snprintf(out->endpoint, sizeof(out->endpoint), "(unparseable)");
        return 0;   /* unparseable → down */
    }
    out->proto = (u.scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
    /* Label on host:port only — never the path (PII-free metric/label contract). */
    snprintf(out->endpoint, sizeof(out->endpoint), "%s:%d", u.host, u.port);

    t0 = xrdc_mono_ns();
    if (xrdc_connect(&c, &u, &a->conn, &st) != 0) {
        out->connect_ms = (double) (xrdc_mono_ns() - t0) / 1e6;
        return 0;   /* down — reported, not an error */
    }
    out->up = 1;
    out->connect_ms = (double) (xrdc_mono_ns() - t0) / 1e6;
    if (a->probe_timeout_ms > 0) { c.io.timeout_ms = a->probe_timeout_ms; }

    xrdc_netdiag_facts(&c, &f);
    out->tcp_ms = f.tcp_ms;
    out->tls_ms = f.tls_ms;
    out->auth_ms = f.auth_ms;
    {
        const char *ver = NULL, *cipher = NULL;
        out->tls_active = (xrdc_tls_info(&c, &ver, &cipher) == 1);
    }

    /* tiny read (TTFB) against the biggest regular file under the namespace */
    xrdc_status_clear(&st);
    if (resolve_target(&c, &u, target, sizeof(target), &sti, &st) == 0) {
        xrdc_file   fh;
        xrdc_status rst;
        xrdc_status_clear(&rst);
        t0 = xrdc_mono_ns();
        if (xrdc_file_open_read(&c, target, &fh, &rst) == 0) {
            char    b[4096];
            ssize_t got = xrdc_file_read(&c, &fh, 0, b, sizeof(b), &rst);
            if (got >= 0) {
                out->read_ms = (double) (xrdc_mono_ns() - t0) / 1e6;
            }
            xrdc_file_close(&c, &fh, &rst);
        }
        {
            char        lb[8192];
            xrdc_status lst;
            uint64_t    l0 = xrdc_mono_ns();
            xrdc_status_clear(&lst);
            if (xrdc_locate(&c, target, lb, sizeof(lb), &lst) == 0) {
                out->locate_ms = (double) (xrdc_mono_ns() - l0) / 1e6;
                out->holders = watch_count_tokens(lb);
            }
        }
    }
    xrdc_close(&c);
    return 0;
}

static void
watch_emit_human(const watch_sample *s, FILE *out)
{
    fprintf(out, "%-40s up=%d connect=%.1fms", s->endpoint, s->up, s->connect_ms);
    if (s->up) {
        if (s->read_ms >= 0)   { fprintf(out, " read=%.1fms", s->read_ms); }
        if (s->locate_ms >= 0) { fprintf(out, " locate=%.1fms holders=%d",
                                          s->locate_ms, s->holders); }
        fprintf(out, " tls=%d", s->tls_active);
    }
    fputc('\n', out);
}

static void
watch_emit_json(const watch_sample *s, FILE *out)
{
    fputs("{\"endpoint\":", out);
    fjson_str(out, s->endpoint);
    fprintf(out, ",\"proto\":\"%s\",\"up\":%d,\"connect_ms\":%.3f,"
                 "\"tcp_ms\":%.3f,\"tls_ms\":%.3f,\"auth_ms\":%.3f,"
                 "\"read_ms\":%.3f,\"locate_ms\":%.3f,\"holders\":%d,\"tls\":%d}\n",
            s->proto, s->up, s->connect_ms, s->tcp_ms, s->tls_ms, s->auth_ms,
            s->read_ms, s->locate_ms, s->holders, s->tls_active);
}

/* One metric line for every sample, with HELP/TYPE printed once per metric. */
static void
watch_emit_prom(const watch_sample *samples, int n, FILE *out)
{
    int  i;
    char ep[576], pr[64];

    fputs("# HELP xrootd_probe_up Endpoint reachable (1) or down (0).\n"
          "# TYPE xrootd_probe_up gauge\n", out);
    for (i = 0; i < n; i++) {
        watch_prom_label(samples[i].endpoint, ep, sizeof(ep));
        watch_prom_label(samples[i].proto, pr, sizeof(pr));
        fprintf(out, "xrootd_probe_up{endpoint=\"%s\",proto=\"%s\"} %d\n",
                ep, pr, samples[i].up);
    }
    fputs("# HELP xrootd_probe_connect_seconds Full connect (TCP+TLS+auth).\n"
          "# TYPE xrootd_probe_connect_seconds gauge\n", out);
    for (i = 0; i < n; i++) {
        watch_prom_label(samples[i].endpoint, ep, sizeof(ep));
        watch_prom_label(samples[i].proto, pr, sizeof(pr));
        fprintf(out, "xrootd_probe_connect_seconds{endpoint=\"%s\",proto=\"%s\"} %.6f\n",
                ep, pr, samples[i].connect_ms / 1000.0);
    }
    /* phase split + read/locate only for endpoints that came up */
    fputs("# HELP xrootd_probe_read_seconds Tiny-read time-to-first-byte.\n"
          "# TYPE xrootd_probe_read_seconds gauge\n", out);
    for (i = 0; i < n; i++) {
        if (!samples[i].up || samples[i].read_ms < 0) { continue; }
        watch_prom_label(samples[i].endpoint, ep, sizeof(ep));
        watch_prom_label(samples[i].proto, pr, sizeof(pr));
        fprintf(out, "xrootd_probe_read_seconds{endpoint=\"%s\",proto=\"%s\"} %.6f\n",
                ep, pr, samples[i].read_ms / 1000.0);
    }
    fputs("# HELP xrootd_probe_locate_holders Located replica count.\n"
          "# TYPE xrootd_probe_locate_holders gauge\n", out);
    for (i = 0; i < n; i++) {
        if (!samples[i].up || samples[i].holders < 0) { continue; }
        watch_prom_label(samples[i].endpoint, ep, sizeof(ep));
        watch_prom_label(samples[i].proto, pr, sizeof(pr));
        fprintf(out, "xrootd_probe_locate_holders{endpoint=\"%s\",proto=\"%s\"} %d\n",
                ep, pr, samples[i].holders);
    }
}

/* Write the Prometheus exposition to PATH atomically (tmp + rename) — the
 * node_exporter textfile-collector contract (never expose a half-written file). */
static int
watch_write_prom_atomic(const char *path, const watch_sample *samples, int n,
                        xrdc_status *st)
{
    char  tmp[XRDC_PATH_MAX];
    FILE *f;
    int   fd;

    if ((size_t) snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) >= sizeof(tmp)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "watch: prometheus path too long");
        return -1;
    }
    fd = mkstemp(tmp);
    if (fd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "watch: mkstemp %s: %s",
                        path, strerror(errno));
        return -1;
    }
    f = fdopen(fd, "w");
    if (f == NULL) {
        close(fd);
        (void) unlink(tmp);
        xrdc_status_set(st, XRDC_ESOCK, errno, "watch: fdopen: %s", strerror(errno));
        return -1;
    }
    watch_emit_prom(samples, n, f);
    if (fclose(f) != 0 || rename(tmp, path) != 0) {
        (void) unlink(tmp);
        xrdc_status_set(st, XRDC_ESOCK, errno, "watch: write %s: %s",
                        path, strerror(errno));
        return -1;
    }
    return 0;
}

/* Interruptible sleep: ~200ms granularity so SIGINT stops promptly. */
static void
watch_sleep(int seconds)
{
    int i;
    for (i = 0; i < seconds * 5 && !g_watch_stop; i++) {
        struct timespec ts = { 0, 200L * 1000L * 1000L };
        (void) nanosleep(&ts, NULL);
    }
}

static int
do_watch(const diag_args *a)
{
    struct sigaction sa;
    watch_sample     samples[8];
    int              interval = a->interval_s > 0 ? a->interval_s : 10;
    int              cycle = 0, i;

    if (interval > 86400) { interval = 86400; }   /* bound watch_sleep's seconds*5 */

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = watch_on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (!g_watch_stop) {
        for (i = 0; i < a->nurls; i++) {
            watch_probe_once(a, a->urls[i], &samples[i]);
        }
        if (a->watch_prom) {
            if (a->prom_path != NULL) {
                xrdc_status wst;
                xrdc_status_clear(&wst);
                if (watch_write_prom_atomic(a->prom_path, samples, a->nurls, &wst) != 0) {
                    fprintf(stderr, "xrddiag: %s\n", wst.msg);
                }
            } else {
                watch_emit_prom(samples, a->nurls, stdout);
            }
        } else if (a->json) {
            for (i = 0; i < a->nurls; i++) { watch_emit_json(&samples[i], stdout); }
        } else {
            for (i = 0; i < a->nurls; i++) { watch_emit_human(&samples[i], stdout); }
        }
        fflush(stdout);

        cycle++;
        if (a->count > 0 && cycle >= a->count) { break; }
        if (g_watch_stop) { break; }
        watch_sleep(interval);
    }
    return 0;
}

static void
usage(void)
{
    fprintf(stderr,
        "usage: xrddiag <subcommand> [opts] <url> [...]\n"
        "  subcommands:\n"
        "    check    <url>                        protocol-correctness probes\n"
        "    bench    <url> [-S N] [--sweep]       timed download (single vs streams; knee)\n"
        "    topology <url> [--cluster-url URL]    locate + redirect convergence\n"
        "    status   <url> [--metrics-port N]     pull /metrics and summarise\n"
        "    watch    <url> [url2...] [--interval S] [--count N] [--prometheus[=PATH]] [--json]\n"
        "                       continuous health/SLA probe (connect+read+locate); Ctrl-C to stop\n"
        "    compare  <urlA> --vs-reference <urlB> root-vs-root size/list/md5\n"
        "    compare  <root-url//path> --davs <host[:port]>  cross-protocol oracle\n"
        "    probe-robustness <url> --i-am-authorized  adversarial reject auditor\n"
        "    replay   <file.xrdcap> [--playback <url>]  decode (or re-issue) a capture\n"
        "    srr      <http[s]-url>                 fetch WLCG Storage Resource Reporting\n"
        "    tape     <http[s]-url//path>           drive the WLCG/FRM Tape REST (stage+poll)\n"
        "    remote-doctor <url> [url2 ...] [--json] [--allow-write] [--auth-suite]\n"
        "                       actively diagnose server problems (auth/namespace/read/\n"
        "                       checksum/locate/load; --allow-write adds write+stage probes;\n"
        "                       --auth-suite adds the auth/permissions test-suite:\n"
        "                       anon-bypass, forged/expired-token rejection, scope enforcement)\n"
        "                       MULTI-PROTOCOL: each URL's scheme picks the battery —\n"
        "                       root[s]://, http://, https://, davs://|dav://, s3://|s3s://, cms://\n"
        "                       (every stage: connect/TLS/auth/request/ranges/checksum/listing/\n"
        "                       redirect). [--no-verify-tls] for self-signed HTTPS/davs/s3 endpoints\n"
        "  url: host[:port] or <scheme>://host[:port][/path]\n"
        "  capture a session with: xrdcp/xrdfs --capture <file.xrdcap> ...\n"
        "  opts: --tls --notlsok --noverifyhost --auth <gsi|ztn|unix>\n"
        "        --wire-trace[=N] --timing --probe-timeout <ms>\n");
}

int
main(int argc, char **argv)
{
    diag_args   a;
    const char *sub;
    const char *pos[8] = { NULL };
    int         npos = 0, i;

    if (argc < 2) {
        usage();
        return 50;
    }
    sub = argv[1];
    if (strcmp(sub, "-h") == 0 || strcmp(sub, "--help") == 0) {
        usage();
        return 0;
    }

    memset(&a, 0, sizeof(a));
    a.conn.verify_host = 1;
    a.metrics_port = 9100;
    a.verify_tls = 1;       /* verify HTTPS/davs/s3 peer certs unless --no-verify-tls */
    xrootd_crypto_init();   /* arm libxrdproto SHA-256/HMAC for GSI + sigver */

    for (i = 2; i < argc; i++) {
        const char *p = argv[i];
        if (p[0] == '-' && p[1] != '\0' && strcmp(p, "-") != 0) {
            if (xrdc_opts_parse_arg(&a.conn, argc, argv, &i)) { continue; }
            if ((strcmp(p, "-S") == 0 || strcmp(p, "--streams") == 0) && i + 1 < argc) { a.streams = atoi(argv[++i]); }
            else if (strcmp(p, "--vs-reference") == 0 && i + 1 < argc) { a.ref_url = argv[++i]; }
            else if (strcmp(p, "--metrics-port") == 0 && i + 1 < argc) { a.metrics_port = atoi(argv[++i]); }
            else if (strcmp(p, "--cluster-url") == 0 && i + 1 < argc) { a.cluster_url = argv[++i]; }
            else if (strcmp(p, "--i-am-authorized") == 0 || strcmp(p, "--i-am-authorised") == 0) { a.authorized = 1; }
            else if (strcmp(p, "--probe-timeout") == 0 && i + 1 < argc) { a.probe_timeout_ms = atoi(argv[++i]); }
            else if (strcmp(p, "--playback") == 0 && i + 1 < argc) { a.playback_url = argv[++i]; }
            else if (strcmp(p, "--davs") == 0 && i + 1 < argc) { a.davs = argv[++i]; }
            else if (strcmp(p, "--sweep") == 0) { a.sweep = 1; }
            else if (strcmp(p, "--json") == 0) { a.json = 1; }
            else if (strcmp(p, "--allow-write") == 0) { a.allow_write = 1; }
            else if (strcmp(p, "--auth-suite") == 0) { a.auth_suite = 1; }
            else if (strcmp(p, "--no-verify-tls") == 0) { a.verify_tls = 0; }
            else if (strcmp(p, "--dashboard-port") == 0 && i + 1 < argc) { a.dashboard_port = atoi(argv[++i]); }
            else if (strcmp(p, "--interval") == 0 && i + 1 < argc) { a.interval_s = atoi(argv[++i]); }
            else if (strcmp(p, "--count") == 0 && i + 1 < argc) { a.count = atoi(argv[++i]); }
            else if (strcmp(p, "--prometheus") == 0) { a.watch_prom = 1; }
            else if (strncmp(p, "--prometheus=", 13) == 0) { a.watch_prom = 1; a.prom_path = p + 13; }
            else {
                fprintf(stderr, "xrddiag: unknown option '%s'\n", p);
                usage();
                return 50;
            }
        } else if (npos < (int) (sizeof(pos) / sizeof(pos[0]))) {
            pos[npos++] = p;
        } else {
            fprintf(stderr, "xrddiag: too many arguments (max %zu URLs)\n",
                    sizeof(pos) / sizeof(pos[0]));
            return 50;
        }
    }

    if (npos < 1) {
        usage();
        return 50;
    }
    a.url = pos[0];
    if (a.ref_url == NULL && npos == 2) {
        a.ref_url = pos[1];   /* allow `compare urlA urlB` positional form */
    }
    for (i = 0; i < npos; i++) {       /* remote-doctor: the whole transfer path */
        a.urls[i] = pos[i];
    }
    a.nurls = npos;

    if (strcmp(sub, "remote-doctor") == 0) { return do_remote_doctor(&a); }
    if (strcmp(sub, "watch") == 0)         { return do_watch(&a); }
    if (strcmp(sub, "check") == 0)         { return do_check(&a); }
    if (strcmp(sub, "bench") == 0)         { return do_bench(&a); }
    if (strcmp(sub, "topology") == 0)      { return do_topology(&a); }
    if (strcmp(sub, "status") == 0)        { return do_status(&a); }
    if (strcmp(sub, "compare") == 0)       { return do_compare(&a); }
    if (strcmp(sub, "probe-robustness") == 0) { return do_probe_robustness(&a); }
    if (strcmp(sub, "replay") == 0)        { return do_replay(&a); }
    if (strcmp(sub, "srr") == 0)           { return do_srr(&a); }
    if (strcmp(sub, "tape") == 0)          { return do_tape(&a); }

    fprintf(stderr, "xrddiag: unknown subcommand '%s'\n", sub);
    usage();
    return 50;
}
