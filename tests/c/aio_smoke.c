/*
 * aio_smoke.c — M1 validation for the async transport core (client/lib/aio.c).
 *
 * WHAT: Exercises the epoll loop end-to-end against a real root:// server:
 *        (1) PING FLOOD   — N concurrent kXR_ping requests on one connection all
 *                           come back kXR_ok (streamid demux + pipelining).
 *        (2) READ FANOUT  — a file is created (sync API), reopened for read to get
 *                           a connection-bound fhandle, that connection is attached
 *                           to the loop, and many concurrent kXR_read chunks (incl.
 *                           large reads that force kXR_oksofar) are verified
 *                           byte-exact against a known pattern (demux + reply-body
 *                           accumulation + delivery).
 *        (3) MT CALLS     — several threads each issue blocking brix_aio_call pings
 *                           concurrently over a shared aconn (the sync wrapper +
 *                           cross-thread pipelining the FUSE driver will rely on).
 * WHY:  M1 is the substrate everything else builds on; prove demux/accumulation/
 *       lifetime are correct under heavy in-flight concurrency before layering
 *       resilience (M2) and resumption (M3) on top.
 * HOW:  Builds raw 24-byte ClientRequestHdr buffers (the engine fills streamid +
 *       dlen) and submits them via aio.h. Deterministic file pattern lets the read
 *       callback verify bytes inline.
 *
 * Usage: aio_smoke [endpoint] [remote_path]
 *        endpoint default root://localhost:11199 ; remote_path default /aio_smoke.bin
 */
#include "core/aio/aio.h"
#include "brix.h"
#include "protocols/root/protocol/protocol.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

#define FILE_SIZE   (4 * 1024 * 1024)   /* 4 MiB — large reads force oksofar */
#define PING_FLOOD  256
#define MT_THREADS  8
#define MT_PER      50

/* deterministic byte pattern so a read at any offset is self-verifying */
static uint8_t
pat(int64_t i)
{
    uint64_t x = (uint64_t) i * 1103515245ULL + 12345ULL;
    return (uint8_t) (x >> 16);
}

/* ---- shared completion barrier ---- */
typedef struct {
    pthread_mutex_t mx;
    pthread_cond_t  cv;
    int             remaining;
    int             failures;
} barrier;

static void
barrier_init(barrier *b, int n)
{
    pthread_mutex_init(&b->mx, NULL);
    pthread_cond_init(&b->cv, NULL);
    b->remaining = n;
    b->failures = 0;
}

static void
barrier_done(barrier *b, int ok)
{
    pthread_mutex_lock(&b->mx);
    if (!ok) {
        b->failures++;
    }
    b->remaining--;
    pthread_cond_signal(&b->cv);
    pthread_mutex_unlock(&b->mx);
}

static int
barrier_wait(barrier *b)
{
    pthread_mutex_lock(&b->mx);
    while (b->remaining > 0) {
        pthread_cond_wait(&b->cv, &b->mx);
    }
    int f = b->failures;
    pthread_mutex_unlock(&b->mx);
    return f;
}

/* ---- header builders ---- */
static void
build_ping(uint8_t hdr[XRD_REQUEST_HDR_LEN])
{
    memset(hdr, 0, XRD_REQUEST_HDR_LEN);
    uint16_t rid = htons(kXR_ping);
    memcpy(hdr + 2, &rid, 2);
}

static void
build_read(uint8_t hdr[XRD_REQUEST_HDR_LEN], const uint8_t fhandle[4],
           int64_t offset, uint32_t rlen)
{
    memset(hdr, 0, XRD_REQUEST_HDR_LEN);
    uint16_t rid = htons(kXR_read);
    memcpy(hdr + 2, &rid, 2);
    memcpy(hdr + 4, fhandle, 4);            /* fhandle[4] @ 4  */
    uint64_t off_be = htobe64((uint64_t) offset);
    memcpy(hdr + 8, &off_be, 8);            /* offset[8]  @ 8  */
    uint32_t rl_be = htonl(rlen);
    memcpy(hdr + 16, &rl_be, 4);            /* rlen[4]    @ 16 */
}

/* ---- (1) ping flood ---- */
static void
ping_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen,
        const brix_status *st)
{
    (void) blen;
    barrier *b = (barrier *) ctx;
    int ok = (rc == 0 && kxr == kXR_ok);
    if (!ok && st != NULL) {
        fprintf(stderr, "  ping fail: rc=%d kxr=%d %s\n", rc, kxr, st->msg);
    }
    free(body);
    barrier_done(b, ok);
}

static int
test_ping_flood(brix_aconn *ac)
{
    barrier b;
    barrier_init(&b, PING_FLOOD);
    uint8_t hdr[XRD_REQUEST_HDR_LEN];
    build_ping(hdr);

    for (int i = 0; i < PING_FLOOD; i++) {
        brix_status st;
        if (brix_aio_submit(ac, hdr, NULL, 0, ping_cb, &b, 10000, &st) != 0) {
            fprintf(stderr, "  submit failed: %s\n", st.msg);
            barrier_done(&b, 0);
        }
    }
    int f = barrier_wait(&b);
    printf("[1] ping flood   : %d/%d ok\n", PING_FLOOD - f, PING_FLOOD);
    return f;
}

/* ---- (2) read fanout ---- */
typedef struct {
    barrier *b;
    int64_t  off;
    uint32_t len;
} rdctx;

static void
read_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen,
        const brix_status *st)
{
    rdctx *q = (rdctx *) ctx;
    int ok = 1;
    if (rc != 0 || kxr != kXR_ok) {
        ok = 0;
        if (st != NULL) {
            fprintf(stderr, "  read fail @%lld: rc=%d kxr=%d %s\n",
                    (long long) q->off, rc, kxr, st->msg);
        }
    } else if (blen != q->len) {
        ok = 0;
        fprintf(stderr, "  read short @%lld: got %u want %u\n",
                (long long) q->off, blen, q->len);
    } else {
        for (uint32_t i = 0; i < blen; i++) {
            if (body[i] != pat(q->off + i)) {
                ok = 0;
                fprintf(stderr, "  read mismatch @%lld+%u\n", (long long) q->off, i);
                break;
            }
        }
    }
    free(body);
    barrier *b = q->b;
    free(q);
    barrier_done(b, ok);
}

static int
test_read_fanout(brix_aconn *ac, const uint8_t fhandle[4])
{
    /* mix: 64 KiB tiled chunks across the file + a few 1 MiB reads (force oksofar) */
    int      nchunks = FILE_SIZE / 65536;          /* 64 */
    int      nbig    = 4;
    int      total   = nchunks + nbig;
    barrier  b;
    barrier_init(&b, total);

    for (int i = 0; i < nchunks; i++) {
        rdctx *q = (rdctx *) calloc(1, sizeof(*q));
        q->b = &b;
        q->off = (int64_t) i * 65536;
        q->len = 65536;
        uint8_t hdr[XRD_REQUEST_HDR_LEN];
        build_read(hdr, fhandle, q->off, q->len);
        brix_status st;
        if (brix_aio_submit(ac, hdr, NULL, 0, read_cb, q, 20000, &st) != 0) {
            fprintf(stderr, "  read submit failed: %s\n", st.msg);
            free(q);
            barrier_done(&b, 0);
        }
    }
    for (int i = 0; i < nbig; i++) {
        rdctx *q = (rdctx *) calloc(1, sizeof(*q));
        q->b = &b;
        q->off = (int64_t) i * 1024 * 1024;
        q->len = 1024 * 1024;
        uint8_t hdr[XRD_REQUEST_HDR_LEN];
        build_read(hdr, fhandle, q->off, q->len);
        brix_status st;
        if (brix_aio_submit(ac, hdr, NULL, 0, read_cb, q, 20000, &st) != 0) {
            fprintf(stderr, "  big read submit failed: %s\n", st.msg);
            free(q);
            barrier_done(&b, 0);
        }
    }
    int f = barrier_wait(&b);
    printf("[2] read fanout  : %d/%d ok (incl. %d large reads forcing oksofar)\n",
           total - f, total, nbig);
    return f;
}

/* ---- (3) multi-threaded blocking calls ---- */
typedef struct {
    brix_aconn *ac;
    int         failures;
} mtarg;

static void *
mt_worker(void *arg)
{
    mtarg *a = (mtarg *) arg;
    uint8_t hdr[XRD_REQUEST_HDR_LEN];
    build_ping(hdr);
    for (int i = 0; i < MT_PER; i++) {
        uint16_t kxr = 0;
        brix_status st;
        if (brix_aio_call(a->ac, hdr, NULL, 0, &kxr, NULL, NULL, 10000, &st) != 0
            || kxr != kXR_ok) {
            __atomic_fetch_add(&a->failures, 1, __ATOMIC_RELAXED);
        }
    }
    return NULL;
}

static int
test_mt_calls(brix_aconn *ac)
{
    mtarg a = { ac, 0 };
    pthread_t th[MT_THREADS];
    for (int i = 0; i < MT_THREADS; i++) {
        pthread_create(&th[i], NULL, mt_worker, &a);
    }
    for (int i = 0; i < MT_THREADS; i++) {
        pthread_join(th[i], NULL);
    }
    int total = MT_THREADS * MT_PER;
    printf("[3] mt calls     : %d/%d ok (%d threads x %d)\n",
           total - a.failures, total, MT_THREADS, MT_PER);
    return a.failures;
}

int
main(int argc, char **argv)
{
    const char *endpoint = (argc > 1) ? argv[1] : "root://localhost:11199";
    const char *rpath    = (argc > 2) ? argv[2] : "/aio_smoke.bin";

    brix_status st;
    brix_url    url;
    if (brix_endpoint_parse(endpoint, &url, &st) != 0) {
        fprintf(stderr, "endpoint parse: %s\n", st.msg);
        return 2;
    }

    /* --- create the test file with the known pattern (sync API) --- */
    brix_conn cw;
    if (brix_connect(&cw, &url, NULL, &st) != 0) {
        fprintf(stderr, "connect(writer): %s\n", st.msg);
        return 2;
    }
    brix_file fw;
    if (brix_file_open_write(&cw, rpath, 1 /*force/truncate*/, 0, &fw, &st) != 0) {
        fprintf(stderr, "open(write) %s: %s\n", rpath, st.msg);
        brix_close(&cw);
        return 2;
    }
    {
        uint8_t *blk = (uint8_t *) malloc(65536);
        int64_t off = 0;
        while (off < FILE_SIZE) {
            for (int i = 0; i < 65536; i++) {
                blk[i] = pat(off + i);
            }
            if (brix_file_write(&cw, &fw, off, blk, 65536, &st) != 0) {
                fprintf(stderr, "write @%lld: %s\n", (long long) off, st.msg);
                free(blk);
                brix_close(&cw);
                return 2;
            }
            off += 65536;
        }
        free(blk);
    }
    brix_file_close(&cw, &fw, &st);
    brix_close(&cw);

    /* --- reopen for read; the fhandle is bound to THIS connection --- */
    brix_conn cr;
    if (brix_connect(&cr, &url, NULL, &st) != 0) {
        fprintf(stderr, "connect(reader): %s\n", st.msg);
        return 2;
    }
    brix_file fr;
    if (brix_file_open_read(&cr, rpath, &fr, &st) != 0) {
        fprintf(stderr, "open(read) %s: %s\n", rpath, st.msg);
        brix_close(&cr);
        return 2;
    }

    /* --- hand the reader connection to the loop and run the tests --- */
    brix_loop *loop = brix_loop_create(&st);
    if (loop == NULL) {
        fprintf(stderr, "loop create: %s\n", st.msg);
        brix_close(&cr);
        return 2;
    }
    brix_aconn *ac = brix_aconn_attach(loop, &cr, &st);
    if (ac == NULL) {
        fprintf(stderr, "attach: %s\n", st.msg);
        brix_loop_destroy(loop);
        brix_close(&cr);
        return 2;
    }

    int fails = 0;
    fails += test_ping_flood(ac);
    fails += test_read_fanout(ac, fr.fhandle);
    fails += test_mt_calls(ac);

    /* --- teardown --- */
    brix_aconn_close(ac);
    brix_loop_destroy(loop);
    /* The fhandle is released server-side when cr disconnects; no sync close here
     * (the fd is left non-blocking after detach). */
    (void) fr;
    brix_close(&cr);

    if (fails == 0) {
        printf("\nM1 PASS — async demux + accumulation + sync wrapper all correct\n");
        return 0;
    }
    printf("\nM1 FAIL — %d failures\n", fails);
    return 1;
}
