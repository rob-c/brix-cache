/* Unit test for the phase-70 §5.7 krb5 origin-dispatch wiring in
 * src/fs/cache/origin_protocol_bootstrap.c.
 *
 * The credential ladder that answers an authenticated origin's login advert is
 * built from STATIC helpers (origin_bs_parse_advert, origin_bs_auth_dispatch,
 * origin_bs_auth_krb5), so this harness #includes the translation unit directly
 * and stubs its thin external surface (the origin wire I/O, the four
 * per-protocol auth legs, and — for krb5 — the RAW outbound leg). No nginx core,
 * krb5, or OpenSSL objects are linked — every referenced symbol is defined below.
 *
 * Compiled with -DBRIX_HAVE_KRB5=1 so the REAL krb5 branch of
 * origin_bs_auth_krb5 runs. Since phase-70 §5.7's outbound closure, that branch
 * hands the carried ccache PATH + origin SPN straight to the RAW leg
 * brix_cache_origin_auth_krb5_raw (a "krb5\0"+AP-REQ, the dialect real "&P=krb5"
 * origins speak) — no GSS re-import — so the raw leg is what we stub here, letting
 * us assert SPN/ccache selection and the fail-closed path without a live KDC.
 *
 * Ritual: success (a "&P=krb5,<spn>" advert + a carried ccache routes to the krb5
 * raw leg with the ADVERTISED service principal and the carried ccache PATH; and
 * an advert with a bare "&P=krb5" falls back to the request-time carried principal)
 * + error (advert lacks krb5 → kXR_AuthFailed, no origin auth attempted)
 * + security-negative (the raw leg failing fails CLOSED with kXR_AuthFailed and
 * NEVER falls through to a service credential; and an advert-less kXR_authmore
 * never presents a service credential for a per-user TGT).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Types (brix_cache_fill_t / brix_cache_origin_conn_t) for the stub signatures
 * below; the TU under test is #included after the stubs are defined. */
#include "fs/cache/cache_internal.h"

/* ---- record of which auth leg the dispatch selected ----------------------- */
static const char *g_leg;          /* "gsi"/"ztn"/"sss"/"krb5"/NULL */
static const char *g_krb5_princ;   /* origin service principal handed to krb5 */
static const char *g_krb5_ccache;  /* ccache PATH handed to the raw krb5 leg */
static int         g_raw_ok = 1;   /* toggles the raw krb5 leg success/failure */
static int         g_last_xrd_error;
static const char *g_last_err_msg;

/* ---- nginx surface stubs (no nginx core objects are linked) --------------- */

ngx_pid_t ngx_pid = 4242;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* Real ngx_strnstr semantics (the advert parser needs it; ngx_string.o unlinked). */
u_char *
ngx_strnstr(u_char *s1, char *s2, size_t len)
{
    size_t n = strlen(s2);

    if (n == 0) {
        return s1;
    }
    while (len >= n) {
        if (s1[0] == (u_char) s2[0] && ngx_strncmp(s1, s2, n) == 0) {
            return s1;
        }
        s1++;
        len--;
    }
    return NULL;
}

/* Real ngx_cpystrn semantics (bounded copy, always NUL-terminates). */
u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }
    while (--n) {
        *dst = *src;
        if (*dst == '\0') {
            return dst;
        }
        dst++;
        src++;
    }
    *dst = '\0';
    return dst;
}

/* ---- origin wire stubs (unreached by the parse/dispatch under test) -------- */

int brix_cache_io_send(brix_cache_origin_conn_t *oc, const void *buf, size_t len)
{ (void) oc; (void) buf; (void) len; return 0; }

int brix_cache_read_response(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    uint16_t *status, u_char **body, uint32_t *dlen, uint32_t max_body)
{ (void) t; (void) oc; (void) status; (void) body; (void) dlen; (void) max_body;
  return -1; }

int brix_cache_origin_tls_upgrade(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const ngx_str_t *host)
{ (void) t; (void) oc; (void) host; return 0; }

void
brix_cache_set_error(brix_cache_fill_t *t, int xrd_error, int sys_errno,
    const char *msg)
{
    (void) t; (void) sys_errno;
    g_last_xrd_error = xrd_error;
    g_last_err_msg = msg;
}

/* ---- the four per-protocol auth legs: record selection, do no I/O ---------- */

int brix_cache_origin_auth_gsi(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *gsi_parms, const char *proxy_path)
{ (void) t; (void) oc; (void) gsi_parms; (void) proxy_path; g_leg = "gsi"; return 0; }

int brix_cache_origin_auth_ztn(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const ngx_str_t *token)
{ (void) t; (void) oc; (void) token; g_leg = "ztn"; return 0; }

int brix_cache_origin_auth_sss(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *keytab_path, const char *as_user)
{ (void) t; (void) oc; (void) keytab_path; (void) as_user; g_leg = "sss"; return 0; }

/* The RAW krb5 outbound leg (§5.7 closure): records the ccache PATH + origin SPN
 * it was handed, and fails CLOSED (kXR_AuthFailed) when g_raw_ok is toggled off —
 * mirroring the production leg, whose every crypto failure returns kXR_AuthFailed. */
int brix_cache_origin_auth_krb5_raw(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *ccache_path, const char *origin_spn)
{
    (void) oc;
    g_leg = "krb5";
    g_krb5_ccache = ccache_path;
    g_krb5_princ = origin_spn;
    if (!g_raw_ok) {
        brix_cache_set_error(t, kXR_AuthFailed, 0, "raw krb5 leg failed closed");
        return -1;
    }
    return 0;
}

/* ---- the unit under test -------------------------------------------------- */

#include "fs/cache/origin_protocol_bootstrap.c"

/* Build a minimal fill task + a log so the dispatch's t->c->log is valid. */
static ngx_log_t         test_log;
static ngx_connection_t  test_conn;

static void
reset_state(brix_cache_fill_t *t)
{
    g_leg = NULL;
    g_krb5_princ = NULL;
    g_krb5_ccache = NULL;
    g_raw_ok = 1;
    g_last_xrd_error = 0;
    g_last_err_msg = NULL;
    memset(t, 0, sizeof(*t));
    test_conn.log = &test_log;
    t->c = &test_conn;
}

int
main(void)
{
    brix_cache_fill_t     t;
    origin_auth_advert_t  ad;
    int                   rc;

    /* --- parse: "&P=krb5" sets has_krb5, co-advertised blocks don't confuse it,
     *     and "&P=krb5,<spn>" is captured up to the next '&'. */
    {
        static const char advert[] =
            "P=ztn,v:10000&P=krb5,host/origin.brix.test@BRIX.TEST&P=gsi,v:10600";
        memset(&ad, 0, sizeof(ad));
        origin_bs_parse_advert((const u_char *) advert, sizeof(advert) - 1, &ad);
        assert(ad.needs_auth == 1);
        assert(ad.has_krb5 == 1);
        assert(ad.has_ztn == 1);
        assert(ad.has_gsi == 1);
        assert(strcmp(ad.krb5_princ, "host/origin.brix.test@BRIX.TEST") == 0);
    }
    {
        static const char advert[] = "P=ztn,v:10000&P=gsi,v:10600";
        memset(&ad, 0, sizeof(ad));
        origin_bs_parse_advert((const u_char *) advert, sizeof(advert) - 1, &ad);
        assert(ad.has_krb5 == 0);   /* no krb5 advertised */
        assert(ad.krb5_princ[0] == '\0');
    }

    /* --- success: carried ccache + a "&P=krb5,<spn>" advert routes to the raw krb5
     *     leg with the ADVERTISED service principal and the carried ccache PATH. */
    {
        reset_state(&t);
        ngx_cpystrn((u_char *) t.cred_krb5_ccache,
                    (u_char *) "/tmp/brix-krb5-XXXX", sizeof(t.cred_krb5_ccache));
        ngx_cpystrn((u_char *) t.cred_krb5_princ,
                    (u_char *) "xrootd/gateway.brix.test@BRIX.TEST",
                    sizeof(t.cred_krb5_princ));
        memset(&ad, 0, sizeof(ad));
        ad.needs_auth = 1;
        ad.has_krb5 = 1;
        ngx_cpystrn((u_char *) ad.krb5_princ,
                    (u_char *) "host/origin.brix.test@BRIX.TEST",
                    sizeof(ad.krb5_princ));

        rc = origin_bs_auth_dispatch(&t, NULL, &ad);
        assert(rc == 0);
        assert(g_leg != NULL && strcmp(g_leg, "krb5") == 0);
        /* advertised SPN wins over the request-time carried principal */
        assert(g_krb5_princ != NULL
               && strcmp(g_krb5_princ, "host/origin.brix.test@BRIX.TEST") == 0);
        assert(g_krb5_ccache != NULL
               && strcmp(g_krb5_ccache, "/tmp/brix-krb5-XXXX") == 0);
    }

    /* --- success (fallback): a bare "&P=krb5" advert (no SPN) falls back to the
     *     request-time principal carried on the fill task. */
    {
        reset_state(&t);
        ngx_cpystrn((u_char *) t.cred_krb5_ccache,
                    (u_char *) "/tmp/brix-krb5-XXXX", sizeof(t.cred_krb5_ccache));
        ngx_cpystrn((u_char *) t.cred_krb5_princ,
                    (u_char *) "host/origin.brix.test@BRIX.TEST",
                    sizeof(t.cred_krb5_princ));
        memset(&ad, 0, sizeof(ad));
        ad.needs_auth = 1;
        ad.has_krb5 = 1;   /* bare advert: ad.krb5_princ stays empty */

        rc = origin_bs_auth_dispatch(&t, NULL, &ad);
        assert(rc == 0);
        assert(g_leg != NULL && strcmp(g_leg, "krb5") == 0);
        assert(g_krb5_princ != NULL
               && strcmp(g_krb5_princ, "host/origin.brix.test@BRIX.TEST") == 0);
    }

    /* --- error: advert lacks krb5 → kXR_AuthFailed, no auth leg attempted. */
    {
        reset_state(&t);
        ngx_cpystrn((u_char *) t.cred_krb5_ccache,
                    (u_char *) "/tmp/brix-krb5-XXXX", sizeof(t.cred_krb5_ccache));
        memset(&ad, 0, sizeof(ad));
        ad.needs_auth = 1;
        ad.has_ztn = 1;   /* origin offers ztn, NOT krb5 */

        rc = origin_bs_auth_dispatch(&t, NULL, &ad);
        assert(rc == -1);
        assert(g_leg == NULL);                  /* never dialed any origin leg */
        assert(g_last_xrd_error == kXR_AuthFailed);
    }

    /* --- security-negative: the raw krb5 leg failing fails CLOSED (kXR_AuthFailed)
     *     and NEVER falls through to a service credential — the dispatch returns the
     *     krb5 leg's result with no further leg attempted (g_leg stays "krb5"). */
    {
        reset_state(&t);
        ngx_cpystrn((u_char *) t.cred_krb5_ccache,
                    (u_char *) "/nonexistent/ccache", sizeof(t.cred_krb5_ccache));
        memset(&ad, 0, sizeof(ad));
        ad.needs_auth = 1;
        ad.has_krb5 = 1;
        g_raw_ok = 0;   /* raw leg fails (bad ccache / crypto failure) */

        rc = origin_bs_auth_dispatch(&t, NULL, &ad);
        assert(rc == -1);
        assert(g_leg != NULL && strcmp(g_leg, "krb5") == 0);  /* only krb5 tried */
        assert(g_last_xrd_error == kXR_AuthFailed);
    }

    /* --- security-negative: advert-less kXR_authmore never presents a service
     *     credential when a per-user krb5 TGT is carried. */
    {
        reset_state(&t);
        ngx_cpystrn((u_char *) t.cred_krb5_ccache,
                    (u_char *) "/tmp/brix-krb5-XXXX", sizeof(t.cred_krb5_ccache));

        rc = origin_bs_authmore_fallback(&t, NULL);
        assert(rc == -1);
        assert(g_leg == NULL);
        assert(g_last_xrd_error == kXR_AuthFailed);
    }

    printf("origin_krb5_dispatch: all cases passed\n");
    return 0;
}
