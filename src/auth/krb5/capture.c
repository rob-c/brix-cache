#include "auth/krb5/capture.h"

/*
 * capture.c — round-2 krb5 forwarded-TGT capture (phase-70 §5.7).
 *
 * Implements brix_krb5_capture_fwd_cred() (capture.h): decrypt the KRB_CRED the
 * XrdSeckrb5 client sends after the "fwdtgt" challenge, park the forwarded TGT
 * in a MEMORY ccache and import it as a GSS initiator credential. See capture.h
 * for the contract and ownership rules. Without BRIX_HAVE_KRB5 the file still
 * compiles: the API reports unavailable and returns NGX_ERROR.
 */

#if (BRIX_HAVE_KRB5)

#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

/* Log a krb5 error code as human-readable text, mirroring auth.c's pattern. */
static void
brix_krb5_cap_log(krb5_context kctx, krb5_error_code code, const char *what,
    ngx_log_t *log)
{
    const char *msg = krb5_get_error_message(kctx, code);

    ngx_log_error(NGX_LOG_WARN, log, 0, "brix: krb5 capture: %s: %s",
                  what, msg ? msg : "(no detail)");
    if (msg) {
        krb5_free_error_message(kctx, msg);
    }
}

/*
 * Park a forwarded TGT in a fresh private MEMORY ccache keyed by the client
 * principal.  On any failure the half-built ccache is destroyed and the krb5
 * error is returned (already logged); on success *out_cc owns the ccache.  Split
 * from the capture entry so each stays within the CCN ceiling (standards §4/§8).
 */
static krb5_error_code
brix_krb5_stash_tgt_ccache(krb5_context kctx, krb5_principal client,
    krb5_creds *cred, krb5_ccache *out_cc, ngx_log_t *log)
{
    krb5_ccache     cc = NULL;
    krb5_error_code krc;

    krc = krb5_cc_new_unique(kctx, "MEMORY", NULL, &cc);
    if (krc != 0) {
        brix_krb5_cap_log(kctx, krc, "krb5_cc_new_unique", log);
        return krc;
    }
    krc = krb5_cc_initialize(kctx, cc, client);
    if (krc != 0) {
        brix_krb5_cap_log(kctx, krc, "krb5_cc_initialize", log);
        krb5_cc_destroy(kctx, cc);
        return krc;
    }
    krc = krb5_cc_store_cred(kctx, cc, cred);
    if (krc != 0) {
        brix_krb5_cap_log(kctx, krc, "krb5_cc_store_cred", log);
        krb5_cc_destroy(kctx, cc);
        return krc;
    }
    *out_cc = cc;
    return 0;
}

ngx_int_t
brix_krb5_capture_fwd_cred(void *kctx_v, void *auth_ctx_v, void *client_v,
    const u_char *krb_cred, size_t krb_cred_len,
    void **out_gss_cred, void **out_ccache, ngx_log_t *log)
{
    krb5_context       kctx = kctx_v;
    krb5_auth_context  auth_ctx = auth_ctx_v;
    krb5_principal     client = client_v;
    krb5_data          fwd;
    krb5_creds       **creds = NULL;
    krb5_ccache        cc = NULL;
    krb5_error_code    krc;
    OM_uint32          maj, min;
    gss_cred_id_t      gcred = GSS_C_NO_CREDENTIAL;

    if (kctx == NULL || auth_ctx == NULL || client == NULL
        || krb_cred == NULL || krb_cred_len == 0
        || out_gss_cred == NULL || out_ccache == NULL)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 capture: invalid arguments");
        return NGX_ERROR;
    }

    /*
     * Read the forwarded credential. krb5_rd_cred checks per-message time/replay
     * and addresses only when the auth context still carries those flags from
     * round-1 krb5_rd_req; the peer is already authenticated by the AP exchange,
     * and requiring a replay cache here (or matching addresses on an addressless
     * forwarded ticket) buys nothing, so clear the flags for this single read.
     */
    (void) krb5_auth_con_setflags(kctx, auth_ctx, 0);

    fwd.data = (char *) krb_cred;
    fwd.length = (unsigned int) krb_cred_len;

    krc = krb5_rd_cred(kctx, auth_ctx, &fwd, &creds, NULL);
    if (krc != 0) {
        brix_krb5_cap_log(kctx, krc, "krb5_rd_cred", log);
        return NGX_ERROR;
    }
    if (creds == NULL || creds[0] == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 capture: KRB_CRED carried no credential");
        if (creds) {
            krb5_free_tgt_creds(kctx, creds);
        }
        return NGX_ERROR;
    }

    /* Park the forwarded TGT in a private in-memory ccache keyed by the user. */
    krc = brix_krb5_stash_tgt_ccache(kctx, client, creds[0], &cc, log);
    krb5_free_tgt_creds(kctx, creds);
    if (krc != 0) {
        return NGX_ERROR;
    }

    /* Import the ccache as a GSS initiator credential (acts AS the user). */
    maj = gss_krb5_import_cred(&min, cc, NULL, NULL, &gcred);
    if (GSS_ERROR(maj)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 capture: gss_krb5_import_cred failed"
                      " (major=0x%xL minor=0x%xL)",
                      (unsigned long) maj, (unsigned long) min);
        krb5_cc_destroy(kctx, cc);
        return NGX_ERROR;
    }

    /* The GSS cred references the ccache; ownership of both passes to caller. */
    *out_gss_cred = gcred;
    *out_ccache = cc;
    return NGX_OK;
}

#else  /* !BRIX_HAVE_KRB5 */

ngx_int_t
brix_krb5_capture_fwd_cred(void *kctx, void *auth_ctx, void *client,
    const u_char *krb_cred, size_t krb_cred_len,
    void **out_gss_cred, void **out_ccache, ngx_log_t *log)
{
    (void) kctx; (void) auth_ctx; (void) client;
    (void) krb_cred; (void) krb_cred_len;
    (void) out_gss_cred; (void) out_ccache;

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix: krb5 capture: built without krb5/GSSAPI support");
    return NGX_ERROR;
}

#endif /* BRIX_HAVE_KRB5 */
