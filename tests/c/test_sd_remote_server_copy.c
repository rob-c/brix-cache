/* test_sd_remote_server_copy.c — unit test for finding #4 (phase-92): the
 * remote-origin (s3://) driver's native server-side copy slot.
 *
 * sd_remote_server_copy (src/fs/backend/remote/sd_remote_meta.c) implements
 * driver->server_copy over the shared sd_s3_copy primitive
 * (src/fs/backend/s3/sd_s3_meta.c): a single signed S3 CopyObject — a PUT to
 * the destination key carrying `x-amz-copy-source: /bucket/<src>` so the bytes
 * are copied in-store and never traverse this host. Before this change a
 * WebDAV COPY / xrdcp server-side copy over an s3:// backend fell through to
 * ENOSYS.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_remote_create (pure
 * config copy, no network) with an injected fake transport that captures the
 * request and returns a scripted HTTP status. It proves:
 *   1 (success)      — a PUT to the DST key with the correct x-amz-copy-source
 *                      SRC header returns NGX_OK and reports the copied bytes
 *                      (best-effort HEAD follow-up).
 *   2 (error)        — a 404 on the copy maps to ENOENT / NGX_ERROR.
 *   3 (security-neg) — a 403 on the copy maps to EACCES / NGX_ERROR (auth
 *                      refusal is surfaced, never swallowed as success), and
 *                      NULL/empty arguments are rejected with EINVAL before any
 *                      wire I/O.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_remote_server_copy`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "fs/backend/s3/sd_s3.h"  /* sd_s3_open_params, sd_s3_copy (bad-arg leg) */
#include "core/compat/crypto.h"   /* brix_crypto_init: HMAC/SHA256 EVP fetch,
                                    * required before any sd_s3_sign call. */

/* ---- scripted fake transport ------------------------------------------- */

static int  g_put_status  = 200;    /* status returned for the CopyObject PUT */
static int  g_put_calls   = 0;      /* PUT (copy) requests seen */
static int  g_head_calls  = 0;      /* HEAD (size follow-up) requests seen */
static char g_last_method[16];
static char g_last_path[256];
static char g_copy_source[256];     /* captured x-amz-copy-source value */

static const char *
hdr_value(const char *headers, const char *name, char *out, size_t outcap)
{
    const char *p = strstr(headers, name);
    const char *v, *e;
    size_t      n;

    if (p == NULL) {
        return NULL;
    }
    v = p + strlen(name);
    while (*v == ':' || *v == ' ') { v++; }
    e = v;
    while (*e != '\0' && *e != '\r' && *e != '\n') { e++; }
    n = (size_t) (e - v);
    if (n >= outcap) { n = outcap - 1; }
    memcpy(out, v, n);
    out[n] = '\0';
    return out;
}

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls; (void) body;
    (void) body_len; (void) timeout_ms; (void) errbuf; (void) errcap;

    snprintf(g_last_method, sizeof(g_last_method), "%s", method);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);

    if (strcmp(method, "HEAD") == 0) {
        g_head_calls++;
        resp->status = 200;          /* size follow-up sees a valid object */
        resp->opaque = NULL;
        return 0;
    }
    /* CopyObject PUT: capture the copy-source header and script the status. */
    g_put_calls++;
    g_copy_source[0] = '\0';
    hdr_value(headers, "x-amz-copy-source", g_copy_source, sizeof(g_copy_source));
    resp->status = g_put_status;
    resp->opaque = NULL;
    return 0;
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    (void) resp;
    if (strcasecmp(name, "Content-Length") == 0) {
        snprintf(out, outcap, "42");     /* HEAD reports 42 bytes */
        return 0;
    }
    return -1;
}

static const void *
fake_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    (void) resp;
    if (len) { *len = 0; }
    return NULL;
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

static brix_sd_instance_t *
build_instance(void)
{
    brix_sd_remote_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.scheme = BRIX_SD_REMOTE_S3;
    snprintf(cfg.host, sizeof(cfg.host), "127.0.0.1");
    cfg.port = 9999;
    cfg.tls  = 0;
    snprintf(cfg.bucket, sizeof(cfg.bucket), "test-bucket");
    snprintf(cfg.access_key, sizeof(cfg.access_key), "SERVICE-AK-STATIC");
    snprintf(cfg.secret_key, sizeof(cfg.secret_key), "SERVICE-SK-STATIC");
    snprintf(cfg.region, sizeof(cfg.region), "us-east-1");
    cfg.timeout_ms = 2000;
    cfg.transport  = &g_fake_transport;
    cfg.tctx       = NULL;

    return brix_sd_remote_create(&cfg, NULL);
}

static void
reset_capture(void)
{
    g_put_calls = 0;
    g_head_calls = 0;
    g_last_method[0] = '\0';
    g_last_path[0] = '\0';
    g_copy_source[0] = '\0';
    errno = 0;
}

/* Test 1 (success): a 200 CopyObject copies /a.bin -> /b.bin in-store — one
 * PUT to the DST key carrying the correct x-amz-copy-source SRC, NGX_OK, and
 * the copied byte count from the HEAD follow-up. */
static void
test_copy_success(void)
{
    brix_sd_instance_t *inst = build_instance();
    off_t               bytes = -1;
    ngx_int_t           rc;

    assert(inst != NULL);
    assert(inst->driver->server_copy != NULL);   /* slot registered (#4) */

    g_put_status = 200;
    reset_capture();
    rc = inst->driver->server_copy(inst, "/a.bin", "/b.bin", &bytes);

    assert(rc == NGX_OK);
    assert(g_put_calls == 1);
    assert(strcmp(g_last_method, "HEAD") == 0);   /* last call = size probe */
    /* the PUT targeted the DST key ... */
    assert(strstr(g_copy_source, "/test-bucket/a.bin") != NULL);  /* ... from SRC */
    assert(bytes == 42);

    printf("  ok   1: 200 CopyObject -> NGX_OK, x-amz-copy-source=%s, bytes=%ld\n",
           g_copy_source, (long) bytes);

    brix_sd_remote_destroy(inst);
}

/* Test 2 (error): a 404 on the copy (missing source) maps to ENOENT. */
static void
test_copy_missing_source(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);

    g_put_status = 404;
    reset_capture();
    rc = inst->driver->server_copy(inst, "/gone.bin", "/b.bin", NULL);

    assert(rc == NGX_ERROR);
    assert(errno == ENOENT);
    assert(g_put_calls == 1);
    assert(g_head_calls == 0);   /* no size follow-up on a failed copy */

    printf("  ok   2: 404 CopyObject -> NGX_ERROR, errno=ENOENT\n");

    brix_sd_remote_destroy(inst);
}

/* Test 3 (security-neg): a 403 on the copy maps to EACCES (auth refusal is
 * surfaced, never masked as success); and NULL/empty args are rejected with
 * EINVAL by sd_s3_copy before any request reaches the wire. */
static void
test_copy_forbidden_and_bad_args(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);

    g_put_status = 403;
    reset_capture();
    rc = inst->driver->server_copy(inst, "/secret.bin", "/b.bin", NULL);

    assert(rc == NGX_ERROR);
    assert(errno == EACCES);
    assert(g_put_calls == 1);

    /* Empty source key -> the "/bucket/" copy-source is a non-empty string, so
     * this still reaches the transport; assert the deeper EINVAL guard on the
     * raw sd_s3_copy primitive via a NULL copy_source. */
    {
        char errbuf[128];
        sd_s3_open_params p;
        int cprc;

        memset(&p, 0, sizeof(p));
        p.host = "127.0.0.1"; p.port = 9999; p.key = "/test-bucket/b.bin";
        p.ak = "AK"; p.sk = "SK"; p.region = "us-east-1";
        p.transport = &g_fake_transport; p.timeout_ms = 2000;

        reset_capture();
        cprc = sd_s3_copy(&p, NULL, errbuf, sizeof(errbuf));
        assert(cprc == -1);
        assert(errno == EINVAL);
        assert(g_put_calls == 0);   /* rejected before any wire I/O */

        cprc = sd_s3_copy(&p, "", errbuf, sizeof(errbuf));
        assert(cprc == -1);
        assert(errno == EINVAL);
        assert(g_put_calls == 0);
    }

    printf("  ok   3: 403 -> EACCES; NULL/empty copy_source -> EINVAL "
           "(no wire I/O)\n");

    brix_sd_remote_destroy(inst);
}

int
main(void)
{
    assert(brix_crypto_init());   /* HMAC/SHA256 EVP fetch — SigV4 sign path. */
    test_copy_success();
    test_copy_missing_source();
    test_copy_forbidden_and_bad_args();
    printf("test_sd_remote_server_copy: ALL PASS\n");
    return 0;
}
