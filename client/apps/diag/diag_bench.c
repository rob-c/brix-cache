/*
 * diag_bench.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"


/* bench — timed download (single vs streams)                          */

double
bench_one(brix_conn *c, const char *target, brix_status *st)
{
    int      fd;
    char     tmpl[] = "/tmp/xrddiag-bench.XXXXXX";
    int64_t  bytes = 0;
    uint64_t t0, t1;
    double   secs;

    fd = mkstemp(tmpl);
    if (fd < 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "mkstemp failed");
        return -1.0;
    }
    t0 = brix_mono_ns();
    if (download_to_fd(c, target, fd, &bytes, st) != 0) {
        close(fd);
        unlink(tmpl);
        return -1.0;
    }
    t1 = brix_mono_ns();
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
void
bench_sweep(brix_conn *c, const char *target)
{
    static const size_t sizes[] = { 65536, 262144, 1048576, 4194304, 16777216 };
    size_t i;

    printf("Read-size sweep:\n");
    printf("  %-10s %12s\n", "req-size", "MB/s");
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        brix_file   f;
        brix_status st;
        uint8_t    *buf;
        int64_t     off = 0;
        uint64_t    t0, t1;
        double      secs;

        brix_status_clear(&st);
        if (brix_file_open_read(c, target, &f, &st) != 0) {
            printf("  %-10zu open: %s\n", sizes[i], st.msg);
            continue;
        }
        buf = (uint8_t *) malloc(sizes[i]);
        if (buf == NULL) {
            brix_file_close(c, &f, &st);
            continue;
        }
        t0 = brix_mono_ns();
        for (;;) {
            ssize_t r = brix_file_read(c, &f, off, buf, sizes[i], &st);
            if (r <= 0) {
                break;
            }
            off += r;
        }
        t1 = brix_mono_ns();
        free(buf);
        brix_file_close(c, &f, &st);
        secs = (double) (t1 - t0) / 1e9;
        if (secs <= 0.0) {
            secs = 1e-9;
        }
        printf("  %-10zu %12.1f\n", sizes[i], (double) off / 1e6 / secs);
    }
}


int
do_bench(const diag_args *a)
{
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    brix_statinfo sti;
    char          target[XRDC_PATH_MAX];
    char          root_url[XRDC_PATH_MAX + 512];   /* scheme + host + ':' + port + path */

    brix_status_clear(&st);
    if (brix_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (brix_connect(&c, &u, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }
    if (resolve_target(&c, &u, target, sizeof(target), &sti, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        brix_close(&c);
        return brix_shellcode(&st);
    }
    printf("Benchmark: %s (%lld bytes)\n", target, (long long) sti.size);
    brix_netdiag_report(&c, stdout);   /* §15.3: phases + family + TCP_INFO */

    if (a->sweep) {                    /* §15.3: read-size knee table, then done */
        bench_sweep(&c, target);
        brix_close(&c);
        return 0;
    }

    if (bench_one(&c, target, &st) < 0.0) {
        fprintf(stderr, "xrddiag: bench: %s\n", st.msg);
        brix_close(&c);
        return brix_shellcode(&st);
    }
    brix_timing_report(&c);
    brix_close(&c);

    /* Streams variant goes through brix_copy, which wires kXR_bind secondaries. */
    if (a->streams > 1) {
        brix_copy_opts co;
        brix_status    cst;
        char           tmpl[] = "/tmp/xrddiag-bench.XXXXXX";
        int            fd = mkstemp(tmpl);
        uint64_t       t0, t1;

        memset(&co, 0, sizeof(co));
        co.force = 1;
        co.silent = 1;
        co.streams = a->streams;
        snprintf(root_url, sizeof(root_url), "%s://%s:%d/%s",
                 a->conn.want_tls ? "roots" : "root", u.host, u.port, target);
        brix_status_clear(&cst);
        if (fd >= 0) {
            close(fd);
        }
        t0 = brix_mono_ns();
        if (brix_copy(root_url, tmpl, &co, &a->conn, &cst) != 0) {
            fprintf(stderr, "xrddiag: bench --streams: %s\n", cst.msg);
        } else {
            t1 = brix_mono_ns();
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
