#include "auth/krb5/apreq.h"

/*
 * apreq.c — raw-krb5 AP-REQ builder for the outbound origin leg (§5.7).
 *
 * Implements the apreq.h contract: turn a delegated user's TGT (carried as a
 * ccache PATH) plus the origin service principal into the "krb5\0"+AP-REQ payload
 * a stock XRootD / brix krb5 acceptor validates with krb5_rd_req. This is the
 * RAW-krb5 dialect the reference implementation actually speaks — the GSSAPI
 * forwarding engine in forward.c speaks gss_init_sec_context tokens instead and
 * cannot authenticate to a real "&P=krb5" origin. The step order mirrors the
 * native client's krb5_acquire() (client/lib/auth/sec/sec_krb5.c) so the two
 * emit byte-identical credentials. Without BRIX_HAVE_KRB5 the file still compiles:
 * the entry reports unavailable and returns NGX_ERROR.
 */

#if (BRIX_HAVE_KRB5)

#include <krb5.h>

/* Log a krb5 error code as human-readable text (mirrors carry.c/capture.c). No
 * ticket or key material is ever logged — only the failing step + krb5's own
 * message string. */
static void
brix_krb5_apreq_log(krb5_context kctx, krb5_error_code code, const char *what,
    ngx_log_t *log)
{
    const char *msg = kctx ? krb5_get_error_message(kctx, code) : NULL;

    ngx_log_error(NGX_LOG_WARN, log, 0, "brix: krb5 apreq: %s: %s",
                  what, msg ? msg : "(no detail)");
    if (msg) {
        krb5_free_error_message(kctx, msg);
    }
}

/*
 * Acquire the ccache/principals/ticket and render the "krb5\0"+AP-REQ payload.
 *
 * Every fallible krb5 step runs here on a created context, writing the acquired
 * resources back through out-params (locals start NULL/zero) so the caller can
 * run one linear NULL-safe cleanup — the same shape as the client's krb5_acquire.
 * Never frees; ownership of every resource stays with the caller.
 */
static ngx_int_t
apreq_acquire(krb5_context ctx, ngx_pool_t *pool, const char *ccache_path,
    const char *origin_spn, krb5_ccache *cc, krb5_principal *client,
    krb5_principal *server, krb5_creds *in_creds, krb5_creds **out_creds,
    krb5_auth_context *auth, krb5_data *apreq, ngx_str_t *out_payload,
    ngx_log_t *log)
{
    krb5_error_code  krc;
    u_char          *p;

    krc = krb5_cc_resolve(ctx, ccache_path, cc);
    if (krc != 0) {
        brix_krb5_apreq_log(ctx, krc, "resolve delegated ccache", log);
        return NGX_ERROR;
    }
    krc = krb5_cc_get_principal(ctx, *cc, client);
    if (krc != 0) {
        brix_krb5_apreq_log(ctx, krc, "delegated ccache has no principal", log);
        return NGX_ERROR;
    }
    krc = krb5_parse_name(ctx, origin_spn, server);
    if (krc != 0) {
        brix_krb5_apreq_log(ctx, krc, "bad origin service principal", log);
        return NGX_ERROR;
    }

    in_creds->client = *client;
    in_creds->server = *server;
    krc = krb5_get_credentials(ctx, 0, *cc, in_creds, out_creds);
    if (krc != 0) {
        brix_krb5_apreq_log(ctx, krc, "cannot get origin service ticket", log);
        return NGX_ERROR;
    }
    krc = krb5_mk_req_extended(ctx, auth, 0, NULL, *out_creds, apreq);
    if (krc != 0) {
        brix_krb5_apreq_log(ctx, krc, "mk_req failed", log);
        return NGX_ERROR;
    }

    /* "krb5\0" (name as a NUL-terminated string, per XrdSecInterface) then the
     * raw AP-REQ — exactly the native client's wire (sec_krb5.c krb5_acquire). */
    p = ngx_pnalloc(pool, 5 + apreq->length);
    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, "krb5", 5);
    ngx_memcpy(p + 5, apreq->data, apreq->length);
    out_payload->data = p;
    out_payload->len  = 5 + (size_t) apreq->length;
    return NGX_OK;
}

ngx_int_t
brix_krb5_apreq_from_ccache(ngx_pool_t *pool, const char *ccache_path,
    const char *origin_spn, ngx_str_t *out_payload, ngx_log_t *log)
{
    krb5_context       ctx = NULL;
    krb5_ccache        cc = NULL;
    krb5_auth_context  auth = NULL;
    krb5_principal     server = NULL, client = NULL;
    krb5_creds         in_creds, *out_creds = NULL;
    krb5_data          apreq;
    krb5_error_code    krc;
    ngx_int_t          rc;

    if (ccache_path == NULL || ccache_path[0] == '\0'
        || origin_spn == NULL || origin_spn[0] == '\0')
    {
        return NGX_ERROR;
    }

    ngx_memzero(&in_creds, sizeof in_creds);
    ngx_memzero(&apreq, sizeof apreq);
    out_payload->data = NULL;
    out_payload->len  = 0;

    krc = krb5_init_context(&ctx);
    if (krc != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 apreq: cannot init context");
        return NGX_ERROR;
    }

    rc = apreq_acquire(ctx, pool, ccache_path, origin_spn, &cc, &client, &server,
                       &in_creds, &out_creds, &auth, &apreq, out_payload, log);

    if (apreq.data != NULL) { krb5_free_data_contents(ctx, &apreq); }
    if (out_creds != NULL)  { krb5_free_creds(ctx, out_creds); }
    if (server != NULL)     { krb5_free_principal(ctx, server); }
    if (auth != NULL)       { krb5_auth_con_free(ctx, auth); }
    if (client != NULL)     { krb5_free_principal(ctx, client); }
    if (cc != NULL)         { krb5_cc_close(ctx, cc); }
    krb5_free_context(ctx);

    return rc;
}

#else  /* !BRIX_HAVE_KRB5 */

ngx_int_t
brix_krb5_apreq_from_ccache(ngx_pool_t *pool, const char *ccache_path,
    const char *origin_spn, ngx_str_t *out_payload, ngx_log_t *log)
{
    (void) pool; (void) ccache_path; (void) origin_spn; (void) out_payload;
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix: krb5 apreq: built without krb5 support");
    return NGX_ERROR;
}

#endif /* BRIX_HAVE_KRB5 */
