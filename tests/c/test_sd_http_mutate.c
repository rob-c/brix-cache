/* test_sd_http_mutate.c — unit test for phase-92 sd_http namespace mutation:
 * the HTTP/WebDAV-origin driver's mkdir (MKCOL) and rename (MOVE) slots.
 *
 * sd_http_mkdir (src/fs/backend/http/sd_http_write.c) issues a WebDAV MKCOL
 * (RFC 4918 §9.3) against the collection URL; 201 Created is success, 405 means
 * the collection already exists, 409 means the parent is missing. sd_http_rename
 * issues a WebDAV MOVE (§9.9) with an absolute Destination: URI composed from
 * endpoint 0 and an Overwrite: header driven by `noreplace` (F = refuse to
 * clobber an existing target -> 412). Both mutate the namespace on endpoint 0
 * only — writes never fail over (a mutation on a non-primary origin would
 * split-brain the store). Before this change these slots were NULL, so the VFS
 * saw CAP_DIRS_WRITE unset and refused mkdir/rename on an http:// export.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_http_create (pure config
 * copy, no network) with an injected fake transport whose reply status is
 * scripted per-call. It proves:
 *   1 (success)      — MKCOL 201 -> NGX_OK, wire method MKCOL on the trailing key;
 *                      MOVE 201 and 204 -> NGX_OK, wire method MOVE with an
 *                      absolute Destination URI (scheme/host/port + dst path) and
 *                      Overwrite: T when noreplace==0; the driver advertises
 *                      CAP_DIRS_WRITE + CAP_HARD_RENAME and both slots are wired.
 *   2 (error)        — MKCOL 404/409 -> ENOENT, 405 -> EEXIST, 401/403 -> EACCES;
 *                      MOVE 404 -> ENOENT; a transport-layer failure -> EIO. Each
 *                      returns NGX_ERROR (never a false success).
 *   3 (security-neg) — a no-replace rename (noreplace==1) MUST send Overwrite: F
 *                      so an existing destination is refused (412 -> EEXIST), never
 *                      silently clobbered; and the refusal surfaces as an error,
 *                      not a masked success.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_http_mutate`.
 */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/http/sd_http.h"

/* ---- ngx + brix link stubs (see test_sd_http_dir.c) — inert on log=NULL. */
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

ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    ngx_uint_t c1, c2;

    while (n) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;
        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;
        if (c1 == c2) {
            if (c1) { n--; continue; }
            return 0;
        }
        return c1 - c2;
    }
    return 0;
}

/* ---- scripted fake transport ------------------------------------------- */

static long g_status      = 201;   /* reply status the next request returns */
static int  g_fail        = 0;     /* 1 -> transport returns non-zero (I/O error) */
static int  g_calls       = 0;
static char g_last_method[16];
static char g_last_path[512];
static char g_last_hdrs[1024];

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls;
    (void) body; (void) body_len; (void) timeout_ms; (void) errbuf; (void) errcap;

    g_calls++;
    snprintf(g_last_method, sizeof(g_last_method), "%s", method);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);
    snprintf(g_last_hdrs, sizeof(g_last_hdrs), "%s", headers ? headers : "");

    resp->opaque = NULL;
    if (g_fail) {
        return -1;                 /* transport-layer failure (never a status) */
    }
    resp->status = g_status;
    return 0;
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    (void) resp; (void) name; (void) out; (void) outcap;
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

/* ---- cred-capable fake transport ---------------------------------------------
 * Adds request_cred (a per-request mutual-TLS client cert) so the x509-proxy
 * namespace path can be exercised, and records the presented cert PATH plus which
 * transport slot fired (request vs request_cred). The plain g_fake_transport above
 * deliberately leaves .request_cred NULL — that is the "cannot present a client
 * cert" transport the deny-mode security test needs. */
static char g_last_cert[512];
static int  g_used_cred_path = 0;   /* 1 iff request_cred (mutual-TLS) fired */

static int
fake_request_cred(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    const char *client_cert_pem, brix_s3_resp_t *resp, char *errbuf,
    size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls;
    (void) body; (void) body_len; (void) timeout_ms; (void) errbuf; (void) errcap;

    g_calls++;
    g_used_cred_path = 1;
    snprintf(g_last_method, sizeof(g_last_method), "%s", method);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);
    snprintf(g_last_hdrs, sizeof(g_last_hdrs), "%s", headers ? headers : "");
    snprintf(g_last_cert, sizeof(g_last_cert), "%s",
             client_cert_pem ? client_cert_pem : "");

    resp->opaque = NULL;
    if (g_fail) {
        return -1;
    }
    resp->status = g_status;
    return 0;
}

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
    cfg.host      = "127.0.0.1";
    cfg.port      = 9999;
    cfg.tls       = 0;
    cfg.base_path = "/base";
    cfg.transport = xport;
    cfg.timeout_ms = 2000;

    return brix_sd_http_create(&cfg, NULL);  /* log=NULL -> logging inert */
}

static brix_sd_instance_t *
build_instance(void)
{
    return build_instance_xport(&g_fake_transport);
}

/* Test 1 (success): MKCOL 201 and MOVE 201/204 -> NGX_OK, correct wire. */
static void
test_mutate_success(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);
    /* driver->caps advertises the mutable catalog + atomic rename; slots wired. */
    assert((inst->driver->caps & BRIX_SD_CAP_DIRS_WRITE) != 0);
    assert((inst->driver->caps & BRIX_SD_CAP_HARD_RENAME) != 0);
    assert(inst->driver->mkdir != NULL);
    assert(inst->driver->rename != NULL);

    /* mkdir: MKCOL on the trailing collection key. */
    g_status = 201; g_fail = 0; g_calls = 0;
    rc = inst->driver->mkdir(inst, "/newdir", 0755);
    assert(rc == NGX_OK);
    assert(g_calls == 1);
    assert(strcmp(g_last_method, "MKCOL") == 0);
    assert(strstr(g_last_path, "/base/newdir") != NULL);

    /* mkdir: 200 is also accepted (some origins answer 200 to MKCOL). */
    g_status = 200; g_fail = 0;
    assert(inst->driver->mkdir(inst, "/newdir2", 0755) == NGX_OK);

    /* rename: MOVE 201 (created) with an absolute Destination + Overwrite: T. */
    g_status = 201; g_fail = 0; g_calls = 0;
    rc = inst->driver->rename(inst, "/a.txt", "/b.txt", 0 /* replace ok */);
    assert(rc == NGX_OK);
    assert(g_calls == 1);
    assert(strcmp(g_last_method, "MOVE") == 0);
    assert(strstr(g_last_path, "/base/a.txt") != NULL);          /* source is the URL */
    assert(strstr(g_last_hdrs, "Destination: http://127.0.0.1:9999/base/b.txt")
           != NULL);                                             /* absolute dst URI */
    assert(strstr(g_last_hdrs, "Overwrite: T") != NULL);         /* replace allowed */

    /* rename: MOVE 204 (destination existed and was replaced) -> NGX_OK. */
    g_status = 204; g_fail = 0;
    assert(inst->driver->rename(inst, "/a.txt", "/b.txt", 0) == NGX_OK);

    printf("  ok   1: MKCOL 201/200 -> OK; MOVE 201/204 -> OK, absolute "
           "Destination + Overwrite: T\n");
    brix_sd_http_destroy(inst);
}

/* Test 2 (error): status/transport failures map to distinct errno, never OK. */
static void
test_mutate_errors(void)
{
    brix_sd_instance_t *inst = build_instance();

    assert(inst != NULL);

    /* mkdir status mapping. */
    g_status = 404; g_fail = 0; errno = 0;
    assert(inst->driver->mkdir(inst, "/x", 0755) == NGX_ERROR && errno == ENOENT);

    g_status = 409; g_fail = 0; errno = 0;   /* parent missing */
    assert(inst->driver->mkdir(inst, "/x", 0755) == NGX_ERROR && errno == ENOENT);

    g_status = 405; g_fail = 0; errno = 0;   /* already exists */
    assert(inst->driver->mkdir(inst, "/x", 0755) == NGX_ERROR && errno == EEXIST);

    g_status = 403; g_fail = 0; errno = 0;
    assert(inst->driver->mkdir(inst, "/x", 0755) == NGX_ERROR && errno == EACCES);

    g_status = 401; g_fail = 0; errno = 0;
    assert(inst->driver->mkdir(inst, "/x", 0755) == NGX_ERROR && errno == EACCES);

    /* mkdir transport-layer failure (no status) -> EIO. */
    g_fail = 1; errno = 0;
    assert(inst->driver->mkdir(inst, "/x", 0755) == NGX_ERROR && errno == EIO);

    /* rename status mapping + transport failure. */
    g_status = 404; g_fail = 0; errno = 0;
    assert(inst->driver->rename(inst, "/a", "/b", 0) == NGX_ERROR
           && errno == ENOENT);

    g_fail = 1; errno = 0;
    assert(inst->driver->rename(inst, "/a", "/b", 0) == NGX_ERROR && errno == EIO);

    printf("  ok   2: MKCOL 404/409->ENOENT, 405->EEXIST, 401/403->EACCES, "
           "xport->EIO; MOVE 404->ENOENT, xport->EIO\n");
    brix_sd_http_destroy(inst);
}

/* Test 3 (security-neg): a no-replace rename must send Overwrite: F so an
 * existing destination is refused (412 -> EEXIST), NEVER silently clobbered. */
static void
test_rename_noreplace_no_clobber(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);

    /* Origin says the destination already exists (Overwrite: F precondition). */
    g_status = 412; g_fail = 0; g_calls = 0; errno = 0;
    rc = inst->driver->rename(inst, "/src.txt", "/exists.txt", 1 /* noreplace */);
    assert(rc == NGX_ERROR);
    assert(errno == EEXIST);                          /* refused, not overwritten */
    assert(g_calls == 1);
    /* The refusal is only trustworthy if we actually asked the origin NOT to
     * clobber — assert the guard header went on the wire. */
    assert(strstr(g_last_hdrs, "Overwrite: F") != NULL);
    assert(strstr(g_last_hdrs, "Overwrite: T") == NULL);

    printf("  ok   3: no-replace MOVE sends Overwrite: F, 412 -> EEXIST "
           "(existing dst never clobbered)\n");
    brix_sd_http_destroy(inst);
}

/* Test 4 (cred success): the *_cred namespace slots thread the requesting user's
 * forwarded credential onto the MKCOL/MOVE/DELETE wire — a WLCG bearer as the
 * Authorization header, an x509 proxy as the mutual-TLS client cert — so the
 * origin authorizes the op AS the user, not the static service credential. This is
 * the source-level guarantee behind the origin-log "operation=mkdir/mv/del
 * subject=alice" evidence. */
static void
test_mutate_cred_success(void)
{
    brix_sd_instance_t *inst = build_instance_xport(&g_fake_transport_cred);
    brix_sd_cred_t      cred;

    assert(inst != NULL);
    /* The credential-scoped namespace slots are wired. */
    assert(inst->driver->mkdir_cred  != NULL);
    assert(inst->driver->rename_cred != NULL);
    assert(inst->driver->unlink_cred != NULL);

    /* Bearer → Authorization header on the plain request path (no client cert). */
    memset(&cred, 0, sizeof(cred));
    cred.bearer = "USER.JWT.ALICE";

    g_status = 201; g_fail = 0; g_calls = 0; g_used_cred_path = 0;
    assert(inst->driver->mkdir_cred(inst, "/d", 0755, &cred) == NGX_OK);
    assert(strcmp(g_last_method, "MKCOL") == 0);
    assert(strstr(g_last_hdrs, "Authorization: Bearer USER.JWT.ALICE") != NULL);
    assert(g_used_cred_path == 0);              /* bearer → plain request path   */

    g_status = 201; g_fail = 0;
    assert(inst->driver->rename_cred(inst, "/a", "/b", 0, &cred) == NGX_OK);
    assert(strcmp(g_last_method, "MOVE") == 0);
    assert(strstr(g_last_hdrs, "Authorization: Bearer USER.JWT.ALICE") != NULL);
    assert(strstr(g_last_hdrs, "Destination: http://127.0.0.1:9999/base/b")
           != NULL);                            /* dst leg carries the user too  */

    g_status = 204; g_fail = 0;
    assert(inst->driver->unlink_cred(inst, "/gone", 0, &cred) == NGX_OK);
    assert(strcmp(g_last_method, "DELETE") == 0);
    assert(strstr(g_last_hdrs, "Authorization: Bearer USER.JWT.ALICE") != NULL);

    /* x509 proxy (no bearer) → presented as the mutual-TLS client cert via the
     * transport's request_cred slot; NOT anonymous, NOT the static header. */
    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy = "/tmp/alice.proxy.pem";
    g_status = 201; g_fail = 0; g_calls = 0; g_used_cred_path = 0;
    g_last_cert[0] = '\0';
    assert(inst->driver->mkdir_cred(inst, "/dx", 0755, &cred) == NGX_OK);
    assert(g_used_cred_path == 1);              /* mutual-TLS request_cred path  */
    assert(strcmp(g_last_cert, "/tmp/alice.proxy.pem") == 0);

    printf("  ok   4: mkdir/rename/unlink_cred thread the user bearer (header) "
           "and x509 proxy (client cert) onto the wire\n");
    brix_sd_http_destroy(inst);
}

/* Test 5 (cred error): an origin that DENIES the forwarded user credential
 * (403/401) surfaces as an error, never a masked success. mkdir/rename map
 * 401/403 → EACCES; unlink's contract maps any non-{204,200,404} → EIO. */
static void
test_mutate_cred_denied_by_origin(void)
{
    brix_sd_instance_t *inst = build_instance_xport(&g_fake_transport_cred);
    brix_sd_cred_t      cred;

    assert(inst != NULL);
    memset(&cred, 0, sizeof(cred));
    cred.bearer = "USER.JWT.ALICE";

    g_status = 403; g_fail = 0; errno = 0;
    assert(inst->driver->mkdir_cred(inst, "/d", 0755, &cred) == NGX_ERROR
           && errno == EACCES);

    g_status = 401; g_fail = 0; errno = 0;
    assert(inst->driver->rename_cred(inst, "/a", "/b", 0, &cred) == NGX_ERROR
           && errno == EACCES);

    g_status = 403; g_fail = 0; errno = 0;
    assert(inst->driver->unlink_cred(inst, "/gone", 0, &cred) == NGX_ERROR
           && errno == EIO);

    printf("  ok   5: origin-denied forwarded-cred mkdir/rename -> EACCES, "
           "unlink -> EIO (never a masked success)\n");
    brix_sd_http_destroy(inst);
}

/* Test 6 (security-neg): a proxy-only credential the transport CANNOT present (no
 * request_cred slot) MUST be refused in deny mode — never silently downgraded to
 * the anonymous/service credential on the wire. The refusal fires BEFORE any wire
 * op (g_calls == 0), so a per-user namespace mutation can never leak onto the
 * service identity. */
static void
test_mutate_cred_no_silent_fallback(void)
{
    brix_sd_instance_t *inst = build_instance_xport(&g_fake_transport);  /* no request_cred */
    brix_sd_cred_t      cred;

    assert(inst != NULL);
    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy    = "/tmp/alice.proxy.pem";   /* proxy-only, no bearer      */
    cred.fallback_deny = 1;                         /* service fallback forbidden */

    g_status = 201; g_fail = 0; g_calls = 0; errno = 0;
    assert(inst->driver->mkdir_cred(inst, "/d", 0755, &cred) == NGX_ERROR);
    assert(errno == EACCES);
    assert(g_calls == 0);                           /* refused BEFORE the wire   */

    g_status = 201; g_fail = 0; g_calls = 0; errno = 0;
    assert(inst->driver->rename_cred(inst, "/a", "/b", 0, &cred) == NGX_ERROR);
    assert(errno == EACCES && g_calls == 0);

    g_status = 204; g_fail = 0; g_calls = 0; errno = 0;
    assert(inst->driver->unlink_cred(inst, "/gone", 0, &cred) == NGX_ERROR);
    assert(errno == EACCES && g_calls == 0);

    printf("  ok   6: proxy-only + deny + no-mutual-TLS transport -> EACCES, "
           "zero wire ops (no silent service-credential fallback)\n");
    brix_sd_http_destroy(inst);
}

int
main(void)
{
    test_mutate_success();
    test_mutate_errors();
    test_rename_noreplace_no_clobber();
    test_mutate_cred_success();
    test_mutate_cred_denied_by_origin();
    test_mutate_cred_no_silent_fallback();
    printf("test_sd_http_mutate: ALL PASS\n");
    return 0;
}
