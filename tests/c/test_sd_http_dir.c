/* test_sd_http_dir.c — unit test for phase-92 sd_http directory enumeration:
 * the HTTP/WebDAV-origin driver's opendir/readdir/closedir (+ opendir_cred).
 *
 * sd_http_opendir (src/fs/backend/http/sd_http_dir.c) issues a WebDAV PROPFIND
 * Depth:1 against the collection URL and turns the 207 Multistatus reply into a
 * POSIX-shaped directory level: each <D:response>'s <D:href> is a child, and a
 * <D:resourcetype><D:collection/> marks it a sub-directory. The self entry (the
 * collection itself) is the shallowest href by '/'-segment count and is skipped
 * regardless of its position in the reply. Before this change opendir on an
 * http:// export hit the NULL slot -> ENOTSUP.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_http_create (pure config
 * copy, no network) with an injected fake transport returning scripted PROPFIND
 * XML. It proves:
 *   1 (success)      — a 207 with self + files + a sub-dir yields the children
 *                      with the right d_type; the request is a PROPFIND with a
 *                      "Depth: 1" header on the trailing-slash collection key; a
 *                      percent-encoded href is decoded; the self entry is skipped
 *                      even when it is NOT first; the stream ends with NGX_DONE.
 *                      Root ("/") enumerates the same way.
 *   2 (error)        — 404 -> ENOENT, 403 -> EACCES, 405 (plain HTTP, no DAV) ->
 *                      ENOTSUP; an auth/absence failure is never masked as an
 *                      empty directory (opendir returns NULL, not an empty dir).
 *   3 (security-neg) — opendir_cred with a proxy-ONLY credential + fallback_deny
 *                      over a transport that cannot present a client cert is
 *                      refused with EACCES (never silently enumerated on the
 *                      anonymous/service identity), and issues NO wire request.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_http_dir`.
 */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/http/sd_http.h"

/* ---- ngx + brix link stubs -------------------------------------------------
 * Instances are built with log=NULL, so sd_http_live_log() short-circuits to
 * NULL and every ngx_log_error site is skipped — these definitions only satisfy
 * the linker; they are never executed on the tested paths. */
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

/* nginx's 7-bit ASCII case-insensitive compare (copied; sd_http_dir.c uses it
 * for namespace-agnostic tag matching). */
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

enum { MODE_OK, MODE_404, MODE_403, MODE_405 };

static int  g_mode        = MODE_OK;
static int  g_calls       = 0;
static char g_last_method[16];
static char g_last_path[512];
static char g_last_hdrs[512];
static const char *g_cur_body = NULL;
static size_t      g_cur_len  = 0;

/* A 207 Multistatus with the SELF entry ("/base/dir/") placed in the MIDDLE of
 * the reply (not first) to prove the depth-based self-skip is order-independent.
 * "sp ace.txt" is percent-encoded in the href to exercise the decoder. Mixed
 * namespace prefixes ("D:" and "lp1:") exercise the prefix-agnostic scanner. */
static const char BODY_OK[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<D:multistatus xmlns:D=\"DAV:\">\n"
    "  <D:response><D:href>/base/dir/file1.txt</D:href>"
    "    <D:propstat><D:prop><lp1:resourcetype/></D:prop>"
    "    <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n"
    "  <D:response><D:href>/base/dir/</D:href>"          /* SELF, mid-list */
    "    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype>"
    "    </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n"
    "  <D:response><D:href>/base/dir/sp%20ace.txt</D:href>" /* pct-encoded */
    "    <D:propstat><D:prop><D:resourcetype/></D:prop>"
    "    <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n"
    "  <lp1:response><lp1:href>/base/dir/subdir/</lp1:href>"  /* child dir */
    "    <lp1:propstat><lp1:prop><lp1:resourcetype><D:collection/>"
    "    </lp1:resourcetype></lp1:prop>"
    "    <lp1:status>HTTP/1.1 200 OK</lp1:status></lp1:propstat></lp1:response>\n"
    "</D:multistatus>\n";

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
    g_cur_body = NULL;
    g_cur_len  = 0;
    switch (g_mode) {
    case MODE_404: resp->status = 404; return 0;
    case MODE_403: resp->status = 403; return 0;
    case MODE_405: resp->status = 405; return 0;
    default: break;
    }
    resp->status = 207;
    g_cur_body = BODY_OK;
    g_cur_len  = strlen(BODY_OK);
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
    if (len) { *len = g_cur_len; }
    return g_cur_body;
}

static void
fake_resp_free(brix_s3_resp_t *resp)
{
    (void) resp;
}

/* Transport WITHOUT request_cred: an origin leg that cannot present a per-user
 * mutual-TLS client cert (drives the proxy-only deny path). */
static const brix_s3_transport_t g_fake_transport = {
    .request     = fake_request,
    .resp_header = fake_resp_header,
    .resp_body   = fake_resp_body,
    .resp_free   = fake_resp_free,
};

static brix_sd_instance_t *
build_instance(void)
{
    brix_sd_http_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host      = "127.0.0.1";
    cfg.port      = 9999;
    cfg.tls       = 0;
    cfg.base_path = "/base";
    cfg.transport = &g_fake_transport;
    cfg.timeout_ms = 2000;

    return brix_sd_http_create(&cfg, NULL);  /* log=NULL -> logging inert */
}

static size_t
drain(brix_sd_dir_t *d, char names[][256], unsigned char *types, size_t cap,
    ngx_int_t *term_rc)
{
    size_t          n = 0;
    brix_sd_dirent_t e;
    ngx_int_t       rc;

    for ( ;; ) {
        rc = d->inst->driver->readdir(d, &e);
        if (rc != NGX_OK) { break; }
        assert(n < cap);
        snprintf(names[n], 256, "%s", e.name);
        types[n] = e.d_type;
        n++;
    }
    *term_rc = rc;
    return n;
}

static int
find_name(char names[][256], size_t n, const char *want, unsigned char *types,
    unsigned char *type_out)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (strcmp(names[i], want) == 0) {
            if (type_out) { *type_out = types[i]; }
            return 1;
        }
    }
    return 0;
}

/* Test 1 (success): PROPFIND Depth:1 on "/dir" -> 3 children (self skipped). */
static void
test_propfind_success(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_dir_t      *d;
    char                names[16][256];
    unsigned char       types[16];
    unsigned char       t;
    int                 err = 0;
    ngx_int_t           term = NGX_OK;
    size_t              n;

    assert(inst != NULL);
    /* driver->caps advertises enumeration (the factory copies it into inst->caps;
     * a direct create leaves inst->caps 0, so assert the driver-honest source). */
    assert((inst->driver->caps & BRIX_SD_CAP_DIRS) != 0);
    assert(inst->driver->opendir != NULL);                  /* slots registered (#2) */
    assert(inst->driver->readdir != NULL);
    assert(inst->driver->closedir != NULL);

    g_mode = MODE_OK;
    g_calls = 0;

    d = inst->driver->opendir(inst, "/dir", &err);
    assert(d != NULL);
    assert(g_calls == 1);                                   /* one PROPFIND */
    assert(strcmp(g_last_method, "PROPFIND") == 0);
    assert(strstr(g_last_hdrs, "Depth: 1") != NULL);        /* immediate children */
    /* base_path + trailing-slash collection key */
    assert(strstr(g_last_path, "/base/dir/") != NULL);

    n = drain(d, names, types, 16, &term);

    assert(term == NGX_DONE);
    assert(n == 3);                                         /* self skipped mid-list */
    assert(find_name(names, n, "file1.txt", types, &t) && t == DT_REG);
    assert(find_name(names, n, "sp ace.txt", types, &t) && t == DT_REG); /* decoded */
    assert(find_name(names, n, "subdir", types, &t) && t == DT_DIR);
    assert(!find_name(names, n, "dir", types, NULL));       /* self never surfaced */
    assert(!find_name(names, n, "", types, NULL));

    inst->driver->closedir(d);
    printf("  ok   1: PROPFIND Depth:1 -> 3 children (self mid-list skipped, "
           "%%20 decoded, subdir DT_DIR), NGX_DONE\n");
    brix_sd_http_destroy(inst);
}

/* Test 1b (root): "/" enumerates the same shape (self-skip works at the root). */
static void
test_propfind_root(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_dir_t      *d;
    char                names[16][256];
    unsigned char       types[16];
    int                 err = 0;
    ngx_int_t           term = NGX_OK;
    size_t              n;

    assert(inst != NULL);
    g_mode = MODE_OK;
    g_calls = 0;

    d = inst->driver->opendir(inst, "/", &err);
    assert(d != NULL);
    assert(strstr(g_last_path, "/base/") != NULL);          /* root collection key */

    n = drain(d, names, types, 16, &term);
    assert(term == NGX_DONE);
    assert(n == 3);                                         /* same body, self skipped */

    inst->driver->closedir(d);
    printf("  ok  1b: root '/' PROPFIND -> children, self skipped at root\n");
    brix_sd_http_destroy(inst);
}

/* Test 2 (error): 404/403/405 surface distinct errno; never an empty dir. */
static void
test_propfind_errors(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_dir_t      *d;
    int                 err;

    assert(inst != NULL);

    g_mode = MODE_404; err = 0;
    d = inst->driver->opendir(inst, "/gone", &err);
    assert(d == NULL && err == ENOENT);                     /* absent, not empty */

    g_mode = MODE_403; err = 0;
    d = inst->driver->opendir(inst, "/secret", &err);
    assert(d == NULL && err == EACCES);                     /* auth refusal surfaced */

    g_mode = MODE_405; err = 0;
    d = inst->driver->opendir(inst, "/plain", &err);
    assert(d == NULL && err == ENOTSUP);                    /* no WebDAV on origin */

    printf("  ok   2: 404->ENOENT, 403->EACCES, 405->ENOTSUP (never empty dir)\n");
    brix_sd_http_destroy(inst);
}

/* Test 3 (security-neg): a proxy-only cred + fallback_deny over a transport that
 * cannot mutual-TLS is refused, NOT silently enumerated on the service identity;
 * and no wire request is issued. */
static void
test_opendir_cred_proxy_deny(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_dir_t      *d;
    brix_sd_cred_t      cred;
    int                 err = 0;

    assert(inst != NULL);
    assert(inst->driver->opendir_cred != NULL);

    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy   = "/tmp/user-proxy.pem";  /* proxy ONLY (no bearer) */
    cred.bearer       = NULL;
    cred.fallback_deny = 1;                      /* service fallback forbidden */

    g_mode = MODE_OK;
    g_calls = 0;

    d = inst->driver->opendir_cred(inst, "/dir", &err, &cred);
    assert(d == NULL);                           /* refused, not anonymous listing */
    assert(err == EACCES);
    assert(g_calls == 0);                        /* refused before any wire I/O */

    printf("  ok   3: proxy-only+deny over non-mTLS transport -> EACCES, no I/O\n");
    brix_sd_http_destroy(inst);
}

int
main(void)
{
    test_propfind_success();
    test_propfind_root();
    test_propfind_errors();
    test_opendir_cred_proxy_deny();
    printf("test_sd_http_dir: ALL PASS\n");
    return 0;
}
