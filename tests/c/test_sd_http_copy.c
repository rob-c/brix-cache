/* test_sd_http_copy.c — unit test for the sd_http server-side copy slots:
 * server_copy / server_copy_cred over WebDAV COPY (RFC 4918 §9.8).
 *
 * Before the slots existed, `drv->server_copy == NULL` on an http:// export made
 * brix_vfs_copy_driver return ENOTSUP, so an intra-origin copy — an xrdcp clone,
 * a WebDAV COPY arriving at the gateway, a TPC whose two legs resolve to the same
 * origin — had to be read down to this host and pushed straight back up: the whole
 * object across the wire twice, for bytes that never needed to leave the store.
 * sd_http_server_copy (src/fs/backend/http/sd_http_mutate.c) issues COPY with the
 * same absolute-Destination request MOVE uses, then best-effort HEADs the
 * destination for the byte count the slot's contract asks for.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_http_create with an
 * injected fake transport whose per-method reply status is scripted. It proves:
 *   1 (success)      — COPY 201/204 -> NGX_OK; the wire method is COPY on the
 *                      SOURCE url with an absolute Destination URI and
 *                      Overwrite: T; *bytes_out is the destination's size from
 *                      the follow-up stat; the driver advertises
 *                      CAP_SERVER_COPY and both slots are wired; the cred slot
 *                      threads a bearer onto BOTH legs and an x509 proxy onto
 *                      the mutual-TLS transport.
 *   2 (error)        — 404 -> ENOENT, 403/401 -> EACCES, 412 -> EEXIST, 507 and
 *                      502 -> EIO, and a transport fault -> EIO; every one is
 *                      NGX_ERROR with the caller's *bytes_out left untouched. A
 *                      COPY that succeeds but whose follow-up stat fails is
 *                      still NGX_OK, with bytes_out 0 (an accounting gap, never
 *                      a failed copy). A NULL bytes_out is accepted.
 *   3 (security-neg) — a 207 Multistatus (a PARTIALLY copied collection) is NOT
 *                      success; a destination that looks like an absolute URL or
 *                      a protocol-relative authority can never move the
 *                      Destination off THIS origin; a mutation never fails over
 *                      to a secondary endpoint (writes are endpoint-0 only, or
 *                      the store split-brains); and a proxy-only credential the
 *                      transport cannot present in deny mode is refused before
 *                      any wire op, never downgraded to the service identity.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_http_copy`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/http/sd_http.h"

/* ---- ngx + brix link stubs (see test_sd_http_mutate.c) — inert on log=NULL.
 * No ngx_string.c function may be stubbed here: the shared sd_http closure links
 * nginx's own string kernel. */
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

/* ---- scripted fake transport -------------------------------------------- */

static long g_copy_status = 201;   /* status the COPY itself answers          */
static long g_head_status = 200;   /* status the follow-up size HEAD answers  */
static long g_size        = 4096;  /* Content-Length that HEAD reports        */
static int  g_fail        = 0;     /* 1 -> transport fault (no status at all) */
static int  g_calls       = 0;
static int  g_copy_calls  = 0;
static int  g_used_cred_path = 0;  /* 1 iff request_cred (mutual-TLS) fired   */
static char g_copy_path[512];
static char g_copy_hdrs[2048];
static char g_copy_host[256];
static char g_last_cert[512];

static void
script_reset(void)
{
    g_copy_status = 201;
    g_head_status = 200;
    g_size        = 4096;
    g_fail        = 0;
    g_calls       = 0;
    g_copy_calls  = 0;
    g_used_cred_path = 0;
    g_copy_path[0] = '\0';
    g_copy_hdrs[0] = '\0';
    g_copy_host[0] = '\0';
    g_last_cert[0] = '\0';
    errno = 0;
}

/* Shared body of both transport slots: record the COPY leg, then answer per
 * method. PROPFIND answers 405 — a file-only origin, so the follow-up stat's
 * type probe never reclassifies the destination as a collection. */
static int
fake_dispatch(const char *host, const char *method, const char *path,
    const char *headers, brix_s3_resp_t *resp)
{
    g_calls++;
    resp->opaque = NULL;
    if (g_fail) {
        return -1;                  /* transport-layer fault (never a status) */
    }
    if (strcmp(method, "COPY") == 0) {
        g_copy_calls++;
        snprintf(g_copy_path, sizeof(g_copy_path), "%s", path);
        snprintf(g_copy_hdrs, sizeof(g_copy_hdrs), "%s", headers ? headers : "");
        snprintf(g_copy_host, sizeof(g_copy_host), "%s", host ? host : "");
        resp->status = g_copy_status;
        return 0;
    }
    if (strcmp(method, "PROPFIND") == 0) {
        resp->status = 405;
        return 0;
    }
    resp->status = g_head_status;   /* HEAD: the follow-up size probe */
    return 0;
}

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) port; (void) tls; (void) body; (void) body_len;
    (void) timeout_ms; (void) errbuf; (void) errcap;

    return fake_dispatch(host, method, path_and_query, headers, resp);
}

static int
fake_request_cred(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    const char *client_cert_pem, brix_s3_resp_t *resp, char *errbuf,
    size_t errcap)
{
    (void) tctx; (void) port; (void) tls; (void) body; (void) body_len;
    (void) timeout_ms; (void) errbuf; (void) errcap;

    g_used_cred_path = 1;
    snprintf(g_last_cert, sizeof(g_last_cert), "%s",
             client_cert_pem ? client_cert_pem : "");
    return fake_dispatch(host, method, path_and_query, headers, resp);
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    (void) resp;
    if (strcasecmp(name, "Content-Length") == 0) {
        snprintf(out, outcap, "%ld", g_size);
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

/* No .request_cred: the "cannot present a client cert" transport the deny-mode
 * security leg needs. */
static const brix_s3_transport_t g_fake_transport = {
    .request     = fake_request,
    .resp_header = fake_resp_header,
    .resp_body   = fake_resp_body,
    .resp_free   = fake_resp_free,
};

static const brix_s3_transport_t g_fake_transport_cred = {
    .request      = fake_request,
    .request_cred = fake_request_cred,
    .resp_header  = fake_resp_header,
    .resp_body    = fake_resp_body,
    .resp_free    = fake_resp_free,
};

static brix_sd_instance_t *
build_instance_xport(const brix_s3_transport_t *xport)
{
    brix_sd_http_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.port       = 9999;
    cfg.tls        = 0;
    cfg.base_path  = "/base";
    cfg.transport  = xport;
    cfg.timeout_ms = 2000;

    return brix_sd_http_create(&cfg, NULL);  /* log=NULL -> logging inert */
}

static brix_sd_instance_t *
build_instance(void)
{
    return build_instance_xport(&g_fake_transport);
}

#define POISON  ((off_t) -424242)

/* Copy with *bytes_out pre-poisoned, so "the slot failed" is observably "the
 * caller's byte count was never written" rather than a plausible-looking 0. */
static ngx_int_t
copy(brix_sd_instance_t *inst, const char *src, const char *dst, off_t *bytes)
{
    *bytes = POISON;
    return inst->driver->server_copy(inst, src, dst, bytes);
}

static void
expect_errno(brix_sd_instance_t *inst, long status, int want_errno)
{
    off_t bytes;

    script_reset();
    g_copy_status = status;
    assert(copy(inst, "/a.txt", "/b.txt", &bytes) == NGX_ERROR);
    assert(errno == want_errno);
    assert(bytes == POISON);        /* no byte count invented for a failure */
}

/* Test 1 (success): COPY 201/204 -> OK, correct wire, byte count reported. */
static void
test_copy_success(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    off_t               bytes;

    assert(inst != NULL);
    /* The cap is what introspection and the config advisor report; it must not
     * disagree with the slot. */
    assert((inst->driver->caps & BRIX_SD_CAP_SERVER_COPY) != 0);
    assert(inst->driver->server_copy != NULL);
    assert(inst->driver->server_copy_cred != NULL);

    script_reset();
    assert(copy(inst, "/a.txt", "/b.txt", &bytes) == NGX_OK);
    assert(g_copy_calls == 1);                          /* ONE in-origin copy  */
    assert(strstr(g_copy_path, "/base/a.txt") != NULL); /* source is the URL   */
    assert(strstr(g_copy_hdrs,
                  "Destination: http://127.0.0.1:9999/base/b.txt") != NULL);
    assert(strstr(g_copy_hdrs, "Overwrite: T") != NULL);
    assert(bytes == 4096);                              /* follow-up stat size */
    /* The bytes never traverse this host: no GET and no PUT went on the wire —
     * the whole point of the slot. */
    assert(g_calls == 2);                               /* COPY + the size HEAD */

    script_reset();
    g_copy_status = 204;                                /* destination replaced */
    g_size = 17;
    assert(copy(inst, "/a.txt", "/b.txt", &bytes) == NGX_OK);
    assert(bytes == 17);

    /* A NULL bytes_out is legal — the caller simply does not want the count. */
    script_reset();
    assert(inst->driver->server_copy(inst, "/a.txt", "/b.txt", NULL) == NGX_OK);
    assert(g_calls == 1);                               /* no follow-up stat   */

    brix_sd_http_destroy(inst);

    /* The credential-scoped slot: a bearer must reach BOTH legs (the origin
     * authorizes the source read and the Destination write as the user), and an
     * x509 proxy must go out as the mutual-TLS client cert. */
    inst = build_instance_xport(&g_fake_transport_cred);
    assert(inst != NULL);

    memset(&cred, 0, sizeof(cred));
    cred.bearer = "USER.JWT.ALICE";
    script_reset();
    bytes = POISON;
    assert(inst->driver->server_copy_cred(inst, "/a.txt", "/b.txt", &bytes,
                                          &cred) == NGX_OK);
    assert(strstr(g_copy_hdrs, "Authorization: Bearer USER.JWT.ALICE") != NULL);
    assert(strstr(g_copy_hdrs,
                  "Destination: http://127.0.0.1:9999/base/b.txt") != NULL);
    assert(g_used_cred_path == 0);            /* bearer rides the plain path   */
    assert(bytes == 4096);

    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy = "/tmp/alice.proxy.pem";
    script_reset();
    assert(inst->driver->server_copy_cred(inst, "/a.txt", "/b.txt", NULL,
                                          &cred) == NGX_OK);
    assert(g_used_cred_path == 1);            /* mutual-TLS request_cred path  */
    assert(strcmp(g_last_cert, "/tmp/alice.proxy.pem") == 0);

    brix_sd_http_destroy(inst);
    printf("  ok   1: COPY 201/204 -> OK with absolute Destination + Overwrite:"
           " T, size from the follow-up stat, no GET/PUT on the wire; cred slot"
           " threads bearer and x509 proxy\n");
}

/* Test 2 (error): every refusal maps to a distinct errno, never a false OK. */
static void
test_copy_errors(void)
{
    brix_sd_instance_t *inst = build_instance();
    off_t               bytes;

    assert(inst != NULL);

    expect_errno(inst, 404, ENOENT);   /* source or destination parent absent  */
    expect_errno(inst, 409, ENOENT);   /* destination parent is not a collection */
    expect_errno(inst, 403, EACCES);
    expect_errno(inst, 401, EACCES);
    expect_errno(inst, 412, EEXIST);   /* Overwrite precondition               */
    expect_errno(inst, 507, EIO);      /* Insufficient Storage                 */
    expect_errno(inst, 502, EIO);

    /* A transport-layer fault carries no status at all. */
    script_reset();
    g_fail = 1;
    assert(copy(inst, "/a.txt", "/b.txt", &bytes) == NGX_ERROR);
    assert(errno == EIO);
    assert(bytes == POISON);

    /* The COPY succeeded; only the follow-up size probe failed. That is an
     * accounting gap in the metric, NOT a failed copy — the bytes are on the
     * origin either way, and reporting NGX_ERROR here would make the caller
     * re-copy them. */
    script_reset();
    g_head_status = 404;
    assert(copy(inst, "/a.txt", "/b.txt", &bytes) == NGX_OK);
    assert(bytes == 0);
    assert(g_copy_calls == 1);

    printf("  ok   2: 404/409->ENOENT, 401/403->EACCES, 412->EEXIST, 507/502 and"
           " a transport fault->EIO, bytes_out untouched; a failed follow-up stat"
           " is still OK with bytes_out 0\n");
    brix_sd_http_destroy(inst);
}

/* A destination is a namespace path, never a URL. Whatever it contains, the
 * Destination header must name THIS origin's authority — a copy that leaves the
 * origin is an exfiltration primitive, not a server-side copy. */
static void
check_destination_stays_on_origin(brix_sd_instance_t *inst)
{
    static const char dest_pfx[] = "Destination: http://127.0.0.1:9999/base/";
    static const char *const smuggled[] = {
        "/http://evil.example/x",     /* an absolute URL smuggled as a path   */
        "//evil.example/x",           /* a protocol-relative authority        */
    };
    size_t i;

    for (i = 0; i < sizeof(smuggled) / sizeof(smuggled[0]); i++) {
        script_reset();
        assert(inst->driver->server_copy(inst, "/a.txt", smuggled[i], NULL)
               == NGX_OK);
        assert(g_copy_calls == 1);
        /* The header block OPENS with the Destination line and its value is
         * anchored on our own authority, so the smuggled text can only ever
         * land in the path segment after it. */
        assert(strncmp(g_copy_hdrs, dest_pfx, sizeof(dest_pfx) - 1) == 0);
        assert(strcmp(g_copy_host, "127.0.0.1") == 0);
    }

    /* A CR or LF in either path would close the Destination line and let what
     * follows be read as a header of the caller's choosing — a second
     * Destination off this origin, or an Authorization replacing ours. Refused
     * outright, before any wire op. */
    script_reset();
    assert(inst->driver->server_copy(inst, "/a.txt",
               "/x\r\nDestination: http://evil.example/y", NULL) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_calls == 0);

    script_reset();
    assert(inst->driver->server_copy(inst, "/a\r\n.txt", "/b.txt", NULL)
           == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_calls == 0);

    /* The same header block backs MOVE, so the refusal must cover rename too. */
    script_reset();
    assert(inst->driver->rename(inst, "/a.txt", "/x\r\nOverwrite: T", 1)
           == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_calls == 0);
}

/* Test 3 (security-negative). */
static void
test_copy_security_neg(void)
{
    brix_sd_instance_t     *inst = build_instance();
    brix_sd_http_ep_cfg_t   extra;
    brix_sd_http_cfg_t      cfg;
    brix_sd_cred_t          cred;
    off_t                   bytes;

    assert(inst != NULL);

    /* 207 Multistatus is how a COLLECTION copy reports that some members failed.
     * A half-copied tree must surface as an error: reported as success, the
     * caller would go on to delete the source of a move. */
    expect_errno(inst, 207, EIO);

    check_destination_stays_on_origin(inst);
    brix_sd_http_destroy(inst);

    /* A mutation never fails over. With a second endpoint configured, the COPY
     * still targets endpoint 0 — a namespace mutation applied to a non-primary
     * origin split-brains the store. */
    memset(&extra, 0, sizeof(extra));
    extra.host = "10.9.9.9";
    extra.port = 8888;
    extra.base_path = "/base";

    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.port       = 9999;
    cfg.base_path  = "/base";
    cfg.transport  = &g_fake_transport;
    cfg.timeout_ms = 2000;
    cfg.extra      = &extra;
    cfg.n_extra    = 1;
    inst = brix_sd_http_create(&cfg, NULL);
    assert(inst != NULL);

    script_reset();
    assert(inst->driver->server_copy(inst, "/a.txt", "/b.txt", NULL) == NGX_OK);
    assert(strcmp(g_copy_host, "127.0.0.1") == 0);
    assert(strstr(g_copy_hdrs, "10.9.9.9") == NULL);

    /* Even when the primary REFUSES, the copy is not retried on the secondary:
     * the refusal is the answer. */
    script_reset();
    g_copy_status = 403;
    assert(inst->driver->server_copy(inst, "/a.txt", "/b.txt", NULL)
           == NGX_ERROR);
    assert(g_copy_calls == 1);
    assert(strcmp(g_copy_host, "127.0.0.1") == 0);
    brix_sd_http_destroy(inst);

    /* A proxy-only credential this transport cannot present, with the service
     * fallback forbidden, is refused BEFORE any wire op — never silently
     * downgraded to copying as the gateway's own identity. */
    inst = build_instance();                       /* no .request_cred */
    assert(inst != NULL);
    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy    = "/tmp/alice.proxy.pem";
    cred.fallback_deny = 1;

    script_reset();
    bytes = POISON;
    assert(inst->driver->server_copy_cred(inst, "/a.txt", "/b.txt", &bytes,
                                          &cred) == NGX_ERROR);
    assert(errno == EACCES);
    assert(g_calls == 0);                          /* refused before the wire */
    assert(bytes == POISON);

    brix_sd_http_destroy(inst);
    printf("  ok   3: 207 partial-collection copy is not success; Destination"
           " never leaves this origin; no failover for a mutation; proxy-only +"
           " deny -> EACCES with zero wire ops\n");
}

int
main(void)
{
    test_copy_success();
    test_copy_errors();
    test_copy_security_neg();
    printf("test_sd_http_copy: ALL PASS\n");
    return 0;
}
