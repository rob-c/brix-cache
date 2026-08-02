/* Unit test for the always-compiled synchronous seams of the phase-70 §5.7
 * inbound krb5 forwarded-TGT delegation-capture state machine
 * (src/auth/krb5/deleg_capture.c).
 *
 * The krb5/GSSAPI capture core is proven live vs a real MIT KDC by
 * tests/test_krb5_forward_live.py (modes "capture"/"carry"); this harness covers
 * the pure glue that surrounds it and needs no KDC:
 *   - brix_krb5_deleg_wanted        (config gate)
 *   - brix_krb5_deleg_credbytes     (round-2 "krb5" prefix / optional-NUL strip)
 *   - brix_krb5_deleg_origin_spn    (request-time gate + origin-SPN derivation)
 *   - brix_krb5_send_fwdtgt         (round-1 kXR_authmore "fwdtgt" wire assembly)
 *
 * It #includes the translation unit directly (compiled WITHOUT BRIX_HAVE_KRB5, so
 * the krb5 block is excluded and no krb5 headers are linked) and stubs the thin
 * external surface: the gbuf/response wire helpers (recorded, not executed), the
 * pool allocators, and the pure origin-principal derivation.
 *
 * Ritual: success (native + NUL-terminated round-2 framing decode; a full gate
 * set derives host/<origin>@<REALM>; the fwdtgt reply is a kXR_authmore carrying
 * "krb5"+"fwdtgt") + error (too-short / non-"krb5" payloads rejected) +
 * security-negative (a missing ccache, disarmed forwarding, or absent origin
 * host/gateway principal all DECLINE the bind — no credential is ever bound).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/ngx_brix_module.h"
#include "auth/gsi/gsi_core.h"                    /* brix_gbuf type */

/* ---- recorded gbuf/wire activity (the real helpers are not linked) --------- */

static char   g_gbuf_raw[8][32];
static size_t g_gbuf_raw_n;
static int    g_gbuf_ended;
static uint16_t g_resp_status;
static int    g_queued;

/* ---- gbuf stubs: record the bucket/raw sequence send_fwdtgt emits ---------- */

void brix_gbuf_init(brix_gbuf *g) { memset(g, 0, sizeof(*g)); g->p = (u_char *) g_gbuf_raw; }
void brix_gbuf_free(brix_gbuf *g) { (void) g; }
void
brix_gbuf_raw(brix_gbuf *g, const void *data, size_t n)
{
    if (g_gbuf_raw_n < 8) {
        size_t c = n < sizeof(g_gbuf_raw[0]) ? n : sizeof(g_gbuf_raw[0]) - 1;
        memcpy(g_gbuf_raw[g_gbuf_raw_n], data, c);
        g_gbuf_raw[g_gbuf_raw_n][c] = '\0';
        g_gbuf_raw_n++;
    }
    g->len += n;
}
void brix_gbuf_u32(brix_gbuf *g, uint32_t v) { (void) v; g->len += 4; }
void brix_gbuf_bucket(brix_gbuf *g, uint32_t t, const void *d, size_t n)
{ (void) t; (void) d; g->len += n; }
void brix_gbuf_end(brix_gbuf *g) { g_gbuf_ended = 1; g->len += 4; }

/* ---- response/wire stubs -------------------------------------------------- */

void
brix_build_resp_hdr(const u_char *streamid, uint16_t status, uint32_t dlen,
    ServerResponseHdr *out)
{ (void) streamid; (void) dlen; (void) out; g_resp_status = status; }

ngx_int_t
brix_queue_response(brix_ctx_t *ctx, ngx_connection_t *c, u_char *buf, size_t n)
{ (void) ctx; (void) c; (void) buf; (void) n; g_queued = 1; return NGX_OK; }

ngx_int_t
brix_send_error(brix_ctx_t *ctx, ngx_connection_t *c, uint16_t code,
    const char *msg)
{ (void) ctx; (void) c; (void) code; (void) msg; return NGX_ERROR; }

/* ---- allocator + log stubs ------------------------------------------------ */

void *ngx_palloc(ngx_pool_t *pool, size_t size) { (void) pool; return malloc(size); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) { (void) pool; return malloc(size); }

ngx_pid_t ngx_pid = 4242;
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{ (void) level; (void) log; (void) err; (void) fmt; }

/* ---- pure origin-principal derivation (proven separately; faithful stub) --- */

ngx_int_t
brix_krb5_origin_princ_from_host(const char *backend_fqdn,
    const char *gateway_princ, char *out, size_t outlen)
{
    const char *realm;
    int         n;

    if (backend_fqdn == NULL || backend_fqdn[0] == '\0'
        || gateway_princ == NULL || out == NULL || outlen == 0
        || strchr(backend_fqdn, '/') != NULL
        || strchr(backend_fqdn, '@') != NULL)
    {
        return NGX_ERROR;
    }
    realm = strchr(gateway_princ, '@');
    if (realm == NULL || realm[1] == '\0') {
        return NGX_ERROR;
    }
    realm++;
    n = snprintf(out, outlen, "host/%s@%s", backend_fqdn, realm);
    if (n <= 0 || (size_t) n >= outlen) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- the unit under test (krb5 block excluded — no BRIX_HAVE_KRB5) --------- */

#include "auth/krb5/deleg_capture.c"

/* ---- fixtures ------------------------------------------------------------- */

static ngx_stream_brix_srv_conf_t  test_conf;
static brix_ctx_t                  test_ctx;
static ngx_connection_t            test_conn;
static ngx_log_t                   test_log;

static ngx_str_t
S(const char *s)
{
    ngx_str_t v;
    v.data = (u_char *) s;
    v.len  = (s != NULL) ? strlen(s) : 0;
    return v;
}

int
main(void)
{
    const u_char *cred;
    size_t        credlen;
    ngx_str_t     spn;
    ngx_str_t     cc_set;
    ngx_str_t     cc_empty;
    ngx_str_t     host;
    ngx_str_t     gwp;
    ngx_int_t     rc;

    /* ================= brix_krb5_deleg_wanted ================= */
    memset(&test_conf, 0, sizeof(test_conf));
    assert(brix_krb5_deleg_wanted(NULL) == 0);
    test_conf.krb5.delegate = 0;
    assert(brix_krb5_deleg_wanted(&test_conf) == 0);
    test_conf.krb5.delegate = 1;
    assert(brix_krb5_deleg_wanted(&test_conf) == 1);

    /* ================= brix_krb5_deleg_credbytes ================= */
    /* success: native (bare "krb5" prefix, no NUL) */
    {
        static const u_char p[] = "krb5\x76\x01\x02\x03";  /* 0x76 = KRB_CRED tag */
        assert(brix_krb5_deleg_credbytes(p, sizeof(p) - 1, &cred, &credlen)
               == NGX_OK);
        assert(credlen == 4 && cred[0] == 0x76);
    }
    /* success: official client NUL-terminates the prefix ("krb5\0" + KRB_CRED) */
    {
        static const u_char p[] = "krb5\x00\x76\xAA\xBB";
        assert(brix_krb5_deleg_credbytes(p, 8, &cred, &credlen) == NGX_OK);
        assert(credlen == 3 && cred[0] == 0x76);
    }
    /* error: too short (prefix only), wrong prefix, and NULL */
    {
        static const u_char shortp[] = "krb5";
        static const u_char wrong[]  = "gsi\x00xx";
        assert(brix_krb5_deleg_credbytes(shortp, 4, &cred, &credlen) == NGX_ERROR);
        assert(brix_krb5_deleg_credbytes(wrong, 6, &cred, &credlen) == NGX_ERROR);
        assert(brix_krb5_deleg_credbytes(NULL, 10, &cred, &credlen) == NGX_ERROR);
    }
    /* edge: "krb5\0" with nothing after the NUL is empty → error, not off-by-one */
    {
        static const u_char p[] = "krb5\x00";
        assert(brix_krb5_deleg_credbytes(p, 5, &cred, &credlen) == NGX_ERROR);
    }

    /* ================= brix_krb5_deleg_origin_spn ================= */
    cc_set   = S("/tmp/brix-krb5-fwd-abc123");
    cc_empty = S("");
    host     = S("origin.example.org");
    gwp      = S("xrootd/gw.example.org@BRIX.TEST");

    /* success: full gate set → derive host/<origin>@<REALM> on the pool */
    rc = brix_krb5_deleg_origin_spn(&cc_set, 1, &host, &gwp,
                                    (ngx_pool_t *) 0x1, &spn);
    assert(rc == NGX_OK);
    assert(spn.len == strlen("host/origin.example.org@BRIX.TEST"));
    assert(memcmp(spn.data, "host/origin.example.org@BRIX.TEST", spn.len) == 0);

    /* security-negative: no captured ccache → DECLINED, nothing bound */
    assert(brix_krb5_deleg_origin_spn(&cc_empty, 1, &host, &gwp,
                                      (ngx_pool_t *) 0x1, &spn) == NGX_DECLINED);
    /* security-negative: forwarding disarmed → DECLINED */
    assert(brix_krb5_deleg_origin_spn(&cc_set, 0, &host, &gwp,
                                      (ngx_pool_t *) 0x1, &spn) == NGX_DECLINED);
    /* security-negative: no configured origin host / gateway principal → DECLINED */
    {
        ngx_str_t none = S("");
        assert(brix_krb5_deleg_origin_spn(&cc_set, 1, &none, &gwp,
                                          (ngx_pool_t *) 0x1, &spn) == NGX_DECLINED);
        assert(brix_krb5_deleg_origin_spn(&cc_set, 1, &host, &none,
                                          (ngx_pool_t *) 0x1, &spn) == NGX_DECLINED);
    }
    /* error: a malformed origin host (already realm-qualified) fails CLOSED */
    {
        ngx_str_t bad = S("origin.example.org@ELSEWHERE");
        assert(brix_krb5_deleg_origin_spn(&cc_set, 1, &bad, &gwp,
                                          (ngx_pool_t *) 0x1, &spn) == NGX_ERROR);
    }

    /* ================= brix_krb5_send_fwdtgt ================= */
    memset(&test_ctx, 0, sizeof(test_ctx));
    memset(&test_conn, 0, sizeof(test_conn));
    test_conn.log = &test_log;
    g_gbuf_raw_n = 0;
    g_gbuf_ended = 0;
    g_resp_status = 0;
    g_queued = 0;

    rc = brix_krb5_send_fwdtgt(&test_ctx, &test_conn);
    assert(rc == NGX_OK);
    assert(g_queued == 1);
    assert(g_resp_status == kXR_authmore);       /* a continuation, not kXR_ok */
    assert(g_gbuf_raw_n == 2);
    assert(strcmp(g_gbuf_raw[0], "krb5") == 0);   /* protocol name */
    assert(strcmp(g_gbuf_raw[1], "fwdtgt") == 0); /* forward-TGT marker */
    assert(g_gbuf_ended == 1);                     /* kXRS_none terminator */

    printf("krb5_deleg_capture: all cases passed\n");
    return 0;
}
