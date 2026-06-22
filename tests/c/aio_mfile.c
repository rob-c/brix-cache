/*
 * aio_mfile.c — M3 validation: transparent file-handle resumption (aio_mgr.c).
 *
 * WHAT: Proves the headline guarantee — a file transfer in progress survives a
 *       server restart with no EIO and byte-exact data:
 *        (1) READ  across a bounce: fill a file, then read it back in chunks while
 *            the server is killed+restarted mid-read; every byte must match.
 *        (2) WRITE across a bounce: write a file in chunks while the server is
 *            bounced mid-write, then re-read it on a fresh handle; byte-exact.
 *       Both rely on xrdc_mfile reopening (fresh handle, non-destructive) and
 *       re-issuing the failed read/write at the same offset (idempotent).
 * WHY:   "Survives a mid-transfer server bounce" — the core M3 deliverable.
 *
 * Usage: XRD_BOUNCE_CMD="<restart server>" aio_mfile [endpoint]
 */
#include "aio.h"
#include "xrdc.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FSIZE        (4 * 1024 * 1024)
#define CHUNK        65536
#define NCHUNK       (FSIZE / CHUNK)   /* 64 */
#define BOUNCE_CHUNK 20

static uint8_t
pat(int64_t i)
{
    uint64_t x = (uint64_t) i * 1103515245ULL + 12345ULL;
    return (uint8_t) (x >> 16);
}

static const char *g_bounce;
static int         g_bounced;

static void
maybe_bounce(int chunk)
{
    if (chunk == BOUNCE_CHUNK && g_bounce != NULL && !g_bounced) {
        g_bounced = 1;
        printf("  >>> bouncing server at chunk %d\n", chunk);
        int rc = system(g_bounce);
        printf("  >>> bounce returned %d\n", rc);
    }
}

/* Fill `path` with the pattern (no bounce). Returns 0/-1. */
static int
fill_file(xrdc_aconn *ac, const char *path)
{
    xrdc_status st;
    xrdc_mfile *mf = xrdc_mfile_open(ac, path, 1 /*writable*/, 1 /*truncate*/,
                                     0, NULL, 20000, 8, &st);
    if (mf == NULL) {
        fprintf(stderr, "fill open: %s\n", st.msg);
        return -1;
    }
    uint8_t blk[CHUNK];
    for (int c = 0; c < NCHUNK; c++) {
        int64_t off = (int64_t) c * CHUNK;
        for (int i = 0; i < CHUNK; i++) {
            blk[i] = pat(off + i);
        }
        if (xrdc_mfile_pwrite(mf, off, blk, CHUNK, &st) != 0) {
            fprintf(stderr, "fill write @%lld: %s\n", (long long) off, st.msg);
            xrdc_mfile_close(mf, &st);
            return -1;
        }
    }
    xrdc_mfile_sync(mf, &st);
    xrdc_mfile_close(mf, &st);
    return 0;
}

/* Read `path` in chunks (optionally bouncing mid-read); verify byte-exact. */
static int
read_verify(xrdc_aconn *ac, const char *path, int do_bounce)
{
    xrdc_status st;
    xrdc_mfile *mf = xrdc_mfile_open(ac, path, 0, 0, 0, NULL, 20000, 8, &st);
    if (mf == NULL) {
        fprintf(stderr, "read open: %s\n", st.msg);
        return -1;
    }
    uint8_t blk[CHUNK];
    int     fails = 0;
    for (int c = 0; c < NCHUNK; c++) {
        if (do_bounce) {
            maybe_bounce(c);
        }
        int64_t off = (int64_t) c * CHUNK;
        ssize_t n = xrdc_mfile_pread(mf, off, blk, CHUNK, &st);
        if (n != CHUNK) {
            fprintf(stderr, "read @%lld got %zd want %d: %s\n",
                    (long long) off, n, CHUNK, (n < 0) ? st.msg : "(short)");
            fails++;
            continue;
        }
        for (int i = 0; i < CHUNK; i++) {
            if (blk[i] != pat(off + i)) {
                fprintf(stderr, "mismatch @%lld+%d\n", (long long) off, i);
                fails++;
                break;
            }
        }
    }
    xrdc_mfile_close(mf, &st);
    return fails;
}

/* Write `path` in chunks while bouncing mid-write. */
static int
write_with_bounce(xrdc_aconn *ac, const char *path)
{
    xrdc_status st;
    xrdc_mfile *mf = xrdc_mfile_open(ac, path, 1, 1 /*truncate*/, 0, NULL,
                                     20000, 8, &st);
    if (mf == NULL) {
        fprintf(stderr, "wbounce open: %s\n", st.msg);
        return -1;
    }
    uint8_t blk[CHUNK];
    int     fails = 0;
    for (int c = 0; c < NCHUNK; c++) {
        maybe_bounce(c);
        int64_t off = (int64_t) c * CHUNK;
        for (int i = 0; i < CHUNK; i++) {
            blk[i] = pat(off + i);
        }
        if (xrdc_mfile_pwrite(mf, off, blk, CHUNK, &st) != 0) {
            fprintf(stderr, "wbounce write @%lld: %s\n", (long long) off, st.msg);
            fails++;
        }
    }
    xrdc_mfile_sync(mf, &st);
    xrdc_mfile_close(mf, &st);
    return fails;
}

int
main(int argc, char **argv)
{
    const char *endpoint = (argc > 1) ? argv[1] : "root://localhost:11199";
    g_bounce = getenv("XRD_BOUNCE_CMD");
    signal(SIGPIPE, SIG_IGN);

    xrdc_status st;
    xrdc_url    url;
    if (xrdc_endpoint_parse(endpoint, &url, &st) != 0) {
        fprintf(stderr, "endpoint parse: %s\n", st.msg);
        return 2;
    }

    xrdc_mgr *mgr = xrdc_mgr_create(&url, NULL, 2, 20000, 3000, 8, &st);
    if (mgr == NULL) {
        fprintf(stderr, "mgr create: %s\n", st.msg);
        return 2;
    }
    xrdc_aconn *ac = xrdc_mgr_pick(mgr);

    int total_fails = 0;

    /* (1) READ across a bounce */
    printf("[1] read across a server bounce\n");
    if (fill_file(ac, "/aio_mfile_r.bin") != 0) {
        xrdc_mgr_destroy(mgr);
        return 2;
    }
    g_bounced = 0;
    int rf = read_verify(ac, "/aio_mfile_r.bin", 1 /*bounce*/);
    printf("    read-across-bounce: %s (%d chunk failures)\n",
           rf == 0 ? "OK" : "FAIL", rf);
    total_fails += rf;

    /* (2) WRITE across a bounce, then verify */
    printf("[2] write across a server bounce, then verify\n");
    g_bounced = 0;
    int wf = write_with_bounce(ac, "/aio_mfile_w.bin");
    int vf = read_verify(ac, "/aio_mfile_w.bin", 0 /*no bounce*/);
    printf("    write-across-bounce: %s (write fails=%d, verify fails=%d)\n",
           (wf == 0 && vf == 0) ? "OK" : "FAIL", wf, vf);
    total_fails += wf + vf;

    xrdc_mgr_destroy(mgr);

    if (total_fails == 0) {
        printf("\nM3 PASS — files survive a mid-transfer server bounce, byte-exact\n");
        return 0;
    }
    printf("\nM3 FAIL — %d failures\n", total_fails);
    return 1;
}
