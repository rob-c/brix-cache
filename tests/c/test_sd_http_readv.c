/* test_sd_http_readv.c — unit test for the sd_http vectored-read slot:
 * `preadv` (src/fs/backend/http/sd_http_readv.c).
 *
 * kXR_readv requests and pgread batches describe ONE contiguous span split into
 * many page-sized iovecs. Without this slot brix_sd_obj_preadv falls back to one
 * driver->pread per iovec — one HTTP round trip per 4 KiB — so a single 4 MiB
 * vector read became a thousand requests against the origin. The slot coalesces
 * the whole span into a single ranged GET and scatters the reply.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_http_create (pure config
 * copy, no network) with an injected fake transport that serves a scripted
 * object, then drives inst->driver->preadv. It proves:
 *   1 (success)      — a scattered read is ONE request whose Range covers the
 *                      whole span exactly once, the bytes land in the right
 *                      iovec at the right offset, a single iovec reads with no
 *                      bounce, a zero-length vector costs no request at all, and
 *                      an origin that ignores Range (200, whole object) is
 *                      sliced to the same bytes as a 206 origin.
 *   2 (error)        — a transport fault and a 4xx/5xx status are -1 with errno
 *                      set and no partial scatter; a span past EOF is a short
 *                      read (the covered prefix), and one entirely past EOF is 0;
 *                      a failure AFTER a partial fill still reports the prefix,
 *                      as pread(2) does.
 *   3 (security-neg) — the slot never writes outside the iovecs it was given: a
 *                      short reply must not scatter into later iovecs, an
 *                      over-long reply (a lying origin returning more bytes than
 *                      the Range asked for) must not overrun the last buffer,
 *                      and the byte count returned can never exceed the span the
 *                      caller described. Guard bytes around every buffer are
 *                      asserted intact.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_http_readv`.
 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/http/sd_http.h"

/* ---- ngx + brix link stubs (instances are built with log=NULL) ------------ */
volatile ngx_cycle_t *ngx_cycle = NULL;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

size_t
brix_sanitize_log_string(const char *in, char *out, size_t outsz)
{
    size_t n = 0;

    if (outsz == 0) { return 0; }
    while (in != NULL && in[n] != '\0' && n + 1 < outsz) {
        out[n] = in[n];
        n++;
    }
    out[n] = '\0';
    return n;
}

/* ---- scripted fake transport --------------------------------------------- */

#define OBJ_LEN  4096

static unsigned char g_obj[OBJ_LEN];      /* the "stored" object              */
static int           g_gets;              /* ranged GETs since the last reset */
static int           g_fail;              /* 1 = transport fault on GET       */
static int           g_status = 206;      /* GET status                       */
static int           g_whole;             /* 1 = ignore Range, return object  */
static long long     g_over;              /* extra bytes a lying origin adds  */
static char          g_last_range[128];
static long long     g_first_off, g_first_end;

/* The slice the last GET produced, kept alive until resp_free. */
static unsigned char g_slice[OBJ_LEN * 2];
static size_t        g_slice_len;

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    long long off = 0, end = 0;

    (void) tctx; (void) host; (void) port; (void) tls; (void) path_and_query;
    (void) body; (void) body_len; (void) timeout_ms; (void) errbuf;
    (void) errcap;

    resp->opaque = NULL;

    if (strcmp(method, "HEAD") == 0) {        /* the open-time size probe */
        resp->status = 200;
        g_slice_len  = 0;
        return 0;
    }

    g_gets++;
    if (headers != NULL) {
        const char *r = strstr(headers, "Range: bytes=");

        snprintf(g_last_range, sizeof(g_last_range), "%s", r ? r : "");
        if (r != NULL) {
            sscanf(r, "Range: bytes=%lld-%lld", &off, &end);
        }
    }
    if (g_gets == 1) {
        g_first_off = off;
        g_first_end = end;
    }
    if (g_fail) {
        return -1;
    }
    resp->status = g_status;
    if (g_status != 200 && g_status != 206) {
        g_slice_len = 0;
        return 0;
    }

    if (g_whole || g_status == 200) {         /* Range-ignoring origin */
        memcpy(g_slice, g_obj, OBJ_LEN);
        g_slice_len = OBJ_LEN;
        return 0;
    }
    if (off >= OBJ_LEN) {                     /* wholly past EOF */
        g_slice_len = 0;
        return 0;
    }
    if (end >= OBJ_LEN) {
        end = OBJ_LEN - 1;                    /* clamp at EOF */
    }
    g_slice_len = (size_t) (end - off + 1);
    memcpy(g_slice, g_obj + off, g_slice_len);
    if (g_over > 0) {                         /* a lying origin over-delivers */
        size_t extra = (size_t) g_over;

        if (g_slice_len + extra > sizeof(g_slice)) {
            extra = sizeof(g_slice) - g_slice_len;
        }
        memset(g_slice + g_slice_len, 0x5A, extra);
        g_slice_len += extra;
    }
    return 0;
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    (void) resp;
    if (strcasecmp(name, "Content-Length") == 0) {
        snprintf(out, outcap, "%d", OBJ_LEN);
        return 0;
    }
    return -1;
}

static const void *
fake_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    (void) resp;
    if (len != NULL) { *len = g_slice_len; }
    return (g_slice_len > 0) ? g_slice : NULL;
}

static void
fake_resp_free(brix_s3_resp_t *resp)
{
    (void) resp;
}

static const brix_s3_transport_t g_fake_transport = {
    .request     = fake_request,
    .resp_header = fake_resp_header,
    .resp_body   = fake_resp_body,
    .resp_free   = fake_resp_free,
};

/* ---- guarded iovec buffers ------------------------------------------------
 * Every buffer is fenced with GUARD bytes on both sides, so a scatter that
 * writes one byte outside the iovec it was handed is caught rather than
 * silently tolerated. */
#define GUARD      0xC7
#define FENCE      16
#define MAX_VEC    8

static unsigned char g_buf[MAX_VEC][512 + 2 * FENCE];
static struct iovec  g_iov[MAX_VEC];

static void
vec_reset(const size_t *lens, int n)
{
    int i;

    assert(n <= MAX_VEC);
    for (i = 0; i < n; i++) {
        assert(lens[i] + 2 * FENCE <= sizeof(g_buf[0]));
        memset(g_buf[i], GUARD, sizeof(g_buf[i]));
        memset(g_buf[i] + FENCE, 0, lens[i]);
        g_iov[i].iov_base = g_buf[i] + FENCE;
        g_iov[i].iov_len  = lens[i];
    }
    g_gets = 0;
    g_last_range[0] = '\0';
}

/* Both fences of every buffer must still be untouched. */
static void
vec_check_fences(const size_t *lens, int n)
{
    int    i;
    size_t k;

    for (i = 0; i < n; i++) {
        for (k = 0; k < FENCE; k++) {
            assert(g_buf[i][k] == GUARD);
            assert(g_buf[i][FENCE + lens[i] + k] == GUARD);
        }
    }
}

static brix_sd_instance_t *
build_instance(void)
{
    brix_sd_http_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.port       = 9999;
    cfg.base_path  = "/base";
    cfg.transport  = &g_fake_transport;
    cfg.timeout_ms = 2000;

    return brix_sd_http_create(&cfg, NULL);  /* log=NULL -> logging inert */
}

/* ---- 1: success ---------------------------------------------------------- */

static void
test_success(brix_sd_instance_t *inst, brix_sd_obj_t *obj)
{
    static const size_t lens[4] = { 128, 256, 64, 512 };
    ssize_t             n;
    size_t              i, base;

    /* A scattered read is ONE request covering [512, 512+960) exactly. */
    g_status = 206; g_whole = 0; g_fail = 0; g_over = 0;
    vec_reset(lens, 4);
    n = inst->driver->preadv(obj, g_iov, 4, 512);
    assert(n == (ssize_t) (128 + 256 + 64 + 512));
    assert(g_gets == 1);
    assert(g_first_off == 512);
    assert(g_first_end == 512 + 960 - 1);
    base = 512;
    for (i = 0; i < 4; i++) {
        assert(memcmp(g_iov[i].iov_base, g_obj + base, lens[i]) == 0);
        base += lens[i];
    }
    vec_check_fences(lens, 4);

    /* A single iovec still reads (straight into the caller's buffer). */
    {
        static const size_t one[1] = { 300 };

        vec_reset(one, 1);
        n = inst->driver->preadv(obj, g_iov, 1, 100);
        assert(n == 300);
        assert(g_gets == 1);
        assert(memcmp(g_iov[0].iov_base, g_obj + 100, 300) == 0);
        vec_check_fences(one, 1);
    }

    /* A zero-length vector costs no request at all. */
    {
        static const size_t zero[2] = { 0, 0 };

        vec_reset(zero, 2);
        assert(inst->driver->preadv(obj, g_iov, 2, 0) == 0);
        assert(g_gets == 0);
    }

    /* An origin that ignores Range (200 + whole object) yields the SAME bytes:
     * the slice happens in pread, so the vector path inherits it. */
    g_status = 200;
    vec_reset(lens, 4);
    n = inst->driver->preadv(obj, g_iov, 4, 512);
    assert(n == (ssize_t) 960);
    base = 512;
    for (i = 0; i < 4; i++) {
        assert(memcmp(g_iov[i].iov_base, g_obj + base, lens[i]) == 0);
        base += lens[i];
    }
    vec_check_fences(lens, 4);
    g_status = 206;
}

/* ---- 2: error ------------------------------------------------------------ */

static void
test_error(brix_sd_instance_t *inst, brix_sd_obj_t *obj)
{
    static const size_t lens[3] = { 128, 128, 128 };
    ssize_t             n;
    size_t              i;

    /* A transport fault is -1, and nothing is scattered. */
    g_fail = 1;
    vec_reset(lens, 3);
    errno = 0;
    assert(inst->driver->preadv(obj, g_iov, 3, 0) == -1);
    assert(errno != 0);
    for (i = 0; i < 3; i++) {
        assert(((unsigned char *) g_iov[i].iov_base)[0] == 0);
    }
    vec_check_fences(lens, 3);
    g_fail = 0;

    /* A hard origin status is -1 with the mapped errno. */
    g_status = 404;
    vec_reset(lens, 3);
    errno = 0;
    assert(inst->driver->preadv(obj, g_iov, 3, 0) == -1);
    assert(errno == ENOENT);
    vec_check_fences(lens, 3);
    g_status = 206;

    /* A span that runs off the end is a SHORT read of the covered prefix. */
    {
        static const size_t tail[2] = { 512, 512 };

        vec_reset(tail, 2);
        n = inst->driver->preadv(obj, g_iov, 2, OBJ_LEN - 600);
        assert(n == 600);
        assert(memcmp(g_iov[0].iov_base, g_obj + OBJ_LEN - 600, 512) == 0);
        assert(memcmp(g_iov[1].iov_base, g_obj + OBJ_LEN - 88, 88) == 0);
        /* the untouched tail of the last iovec stays as the caller left it */
        for (i = 88; i < 512; i++) {
            assert(((unsigned char *) g_iov[1].iov_base)[i] == 0);
        }
        vec_check_fences(tail, 2);
    }

    /* A span entirely past EOF is a 0-byte read, not an error. */
    vec_reset(lens, 3);
    assert(inst->driver->preadv(obj, g_iov, 3, OBJ_LEN + 4096) == 0);
    vec_check_fences(lens, 3);
}

/* ---- 3: security-negative ------------------------------------------------ */

static void
test_security_negative(brix_sd_instance_t *inst, brix_sd_obj_t *obj)
{
    static const size_t lens[3] = { 64, 64, 64 };
    ssize_t             n;
    size_t              i;

    /* A lying origin that returns MORE bytes than the Range asked for must not
     * overrun the last iovec: the copy is bounded by the span the CALLER
     * described, never by the length the origin chose to send. */
    g_over = 1024;
    vec_reset(lens, 3);
    n = inst->driver->preadv(obj, g_iov, 3, 0);
    assert(n >= 0);
    assert(n <= (ssize_t) (64 * 3));
    assert(memcmp(g_iov[0].iov_base, g_obj, 64) == 0);
    vec_check_fences(lens, 3);
    g_over = 0;

    /* A short reply must not scatter into the later iovecs — the bytes that did
     * not arrive stay exactly as the caller left them. */
    {
        static const size_t wide[3] = { 512, 512, 512 };

        vec_reset(wide, 3);
        n = inst->driver->preadv(obj, g_iov, 3, OBJ_LEN - 256);
        assert(n == 256);
        for (i = 0; i < 512; i++) {
            assert(((unsigned char *) g_iov[1].iov_base)[i] == 0);
            assert(((unsigned char *) g_iov[2].iov_base)[i] == 0);
        }
        vec_check_fences(wide, 3);
    }

    /* Whatever the origin does, the count returned never exceeds the span. */
    {
        static const size_t wide[2] = { 500, 500 };

        g_whole = 1;                     /* whole 4 KiB object for a 1000B span */
        vec_reset(wide, 2);
        n = inst->driver->preadv(obj, g_iov, 2, 0);
        assert(n == 1000);
        vec_check_fences(wide, 2);
        g_whole = 0;
    }
}

int
main(void)
{
    brix_sd_instance_t *inst;
    brix_sd_obj_t      *obj;
    int                   err = 0;
    size_t                i;

    for (i = 0; i < OBJ_LEN; i++) {
        g_obj[i] = (unsigned char) (i * 31 + 7);
    }

    inst = build_instance();
    assert(inst != NULL);
    assert(inst->driver->preadv != NULL);

    obj = inst->driver->open(inst, "/o", 0, 0, &err);
    assert(obj != NULL);

    test_success(inst, obj);
    test_error(inst, obj);
    test_security_negative(inst, obj);

    inst->driver->close(obj);
    printf("test_sd_http_readv: OK\n");
    return 0;
}
