#include "auth/krb5/carry.h"

/*
 * carry.c — async-safe carry of a delegated krb5 credential (phase-70 §5.7).
 *
 * Implements the carry.h contract: export a captured GSS initiator credential to
 * a FILE ccache (brix_krb5_cred_to_ccache) and re-acquire it from that path on
 * the async fill task (brix_krb5_cred_from_ccache / _carry_release). The FILE
 * ccache is the serialisable artifact that lets a request-scoped gss_cred_id_t
 * cross into brix_cache_fill_t as a plain path — the same trick the gsi leg uses
 * for x509 proxy PEMs. Without BRIX_HAVE_KRB5 the file still compiles: every entry
 * reports unavailable and returns NGX_ERROR.
 */

#if (BRIX_HAVE_KRB5)

#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>

/* Backing handles kept alive for a re-imported cred's lifetime. The ccache
 * handle from krb5_cc_resolve() is bound to its krb5_context, and
 * gss_krb5_import_cred() retains the handle — so both must outlive the cred and
 * are freed together by brix_krb5_cred_carry_release(). */
typedef struct {
    krb5_context ctx;
    krb5_ccache  cc;
} brix_krb5_carry_hold_t;

/* Log a krb5 error code as human-readable text, mirroring capture.c. */
static void
brix_krb5_carry_log(krb5_context kctx, krb5_error_code code, const char *what,
    ngx_log_t *log)
{
    const char *msg = kctx ? krb5_get_error_message(kctx, code) : NULL;

    ngx_log_error(NGX_LOG_WARN, log, 0, "brix: krb5 carry: %s: %s",
                  what, msg ? msg : "(no detail)");
    if (msg) {
        krb5_free_error_message(kctx, msg);
    }
}

/* Render "FILE:<path>" into buf, bounded. Returns NGX_OK / NGX_ERROR (overflow).
 * A ccache path longer than the buffer is refused rather than silently truncated
 * (a truncated path would resolve to the wrong file). Kept free of ngx_snprintf
 * so the object links into the ngx-core-free krb5 unit harness. */
static ngx_int_t
brix_krb5_file_ccname(const char *path, char *buf, size_t buflen)
{
    static const char prefix[] = "FILE:";
    size_t            plen = sizeof(prefix) - 1;   /* 5, excludes NUL */
    size_t            need;

    need = plen + ngx_strlen(path);
    if (need + 1 > buflen) {                        /* +1 for the NUL */
        return NGX_ERROR;
    }
    ngx_memcpy(buf, prefix, plen);
    ngx_memcpy(buf + plen, path, ngx_strlen(path) + 1);   /* copy incl. NUL */
    return NGX_OK;
}

ngx_int_t
brix_krb5_cred_to_ccache(void *deleg_gss_cred, const char *path, ngx_log_t *log)
{
    char                        ccname[NGX_MAX_PATH + sizeof("FILE:")];
    OM_uint32                   maj, min = 0;
    gss_key_value_element_desc  elem;
    gss_key_value_set_desc      store;

    if (deleg_gss_cred == NULL || path == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 carry: export missing cred/path");
        return NGX_ERROR;
    }

    if (brix_krb5_file_ccname(path, ccname, sizeof(ccname)) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 carry: export ccache path too long");
        return NGX_ERROR;
    }

    /* RFC 5588 gss_store_cred_into with an explicit "ccache" store element writes
     * the initiator cred's forwarded TGT into the named FILE ccache, OVERWRITING
     * it (overwrite=1) so a pre-created 0-byte temp is a clean target — unlike the
     * deprecated gss_krb5_copy_ccache, which cannot initialise and rejects an empty
     * file as "bad format". default_cred=0 keeps it off the process default ccache.
     * libkrb5 creates the FILE 0600. The ccname/deleg_cred are borrowed. */
    elem.key       = "ccache";
    elem.value     = ccname;
    store.count    = 1;
    store.elements = &elem;

    maj = gss_store_cred_into(&min, (gss_cred_id_t) deleg_gss_cred,
                              GSS_C_INITIATE, GSS_C_NO_OID,
                              1 /* overwrite */, 0 /* not default */,
                              &store, NULL, NULL);
    if (GSS_ERROR(maj)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 carry: gss_store_cred_into failed"
                      " (maj=0x%08xui min=0x%08xui)",
                      (ngx_uint_t) maj, (ngx_uint_t) min);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
brix_krb5_cred_from_ccache(const char *path, void **out_gss_cred,
    void **out_hold, ngx_log_t *log)
{
    krb5_context            kctx = NULL;
    krb5_ccache             cc = NULL;
    krb5_error_code         krc;
    gss_cred_id_t           gcred = GSS_C_NO_CREDENTIAL;
    OM_uint32               maj, min = 0;
    brix_krb5_carry_hold_t *hold;
    char                    ccname[NGX_MAX_PATH + sizeof("FILE:")];

    if (path == NULL || out_gss_cred == NULL || out_hold == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 carry: import missing args");
        return NGX_ERROR;
    }
    *out_gss_cred = NULL;
    *out_hold = NULL;

    if (brix_krb5_file_ccname(path, ccname, sizeof(ccname)) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 carry: import ccache path too long");
        return NGX_ERROR;
    }

    hold = malloc(sizeof(brix_krb5_carry_hold_t));
    if (hold == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 carry: import hold alloc failed");
        return NGX_ERROR;
    }

    krc = krb5_init_context(&kctx);
    if (krc != 0) {
        brix_krb5_carry_log(NULL, krc, "krb5_init_context", log);
        free(hold);
        return NGX_ERROR;
    }

    krc = krb5_cc_resolve(kctx, ccname, &cc);
    if (krc != 0) {
        brix_krb5_carry_log(kctx, krc, "krb5_cc_resolve", log);
        krb5_free_context(kctx);
        free(hold);
        return NGX_ERROR;
    }

    maj = gss_krb5_import_cred(&min, cc, NULL, NULL, &gcred);
    if (GSS_ERROR(maj)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 carry: gss_krb5_import_cred failed"
                      " (maj=0x%08xui min=0x%08xui)",
                      (ngx_uint_t) maj, (ngx_uint_t) min);
        krb5_cc_close(kctx, cc);
        krb5_free_context(kctx);
        free(hold);
        return NGX_ERROR;
    }

    hold->ctx = kctx;
    hold->cc = cc;
    *out_gss_cred = gcred;
    *out_hold = hold;
    return NGX_OK;
}

void
brix_krb5_cred_carry_release(void *gss_cred, void *hold_v, ngx_log_t *log)
{
    brix_krb5_carry_hold_t *hold = hold_v;
    OM_uint32               min = 0;

    (void) log;

    if (gss_cred != NULL) {
        gss_cred_id_t g = (gss_cred_id_t) gss_cred;
        (void) gss_release_cred(&min, &g);
    }
    if (hold != NULL) {
        if (hold->cc != NULL) {
            krb5_cc_close(hold->ctx, hold->cc);
        }
        if (hold->ctx != NULL) {
            krb5_free_context(hold->ctx);
        }
        free(hold);
    }
}

#else  /* !BRIX_HAVE_KRB5 */

ngx_int_t
brix_krb5_cred_to_ccache(void *deleg_gss_cred, const char *path, ngx_log_t *log)
{
    (void) deleg_gss_cred; (void) path;
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix: krb5 carry: built without krb5/GSSAPI support");
    return NGX_ERROR;
}

ngx_int_t
brix_krb5_cred_from_ccache(const char *path, void **out_gss_cred,
    void **out_hold, ngx_log_t *log)
{
    (void) path; (void) out_gss_cred; (void) out_hold;
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix: krb5 carry: built without krb5/GSSAPI support");
    return NGX_ERROR;
}

void
brix_krb5_cred_carry_release(void *gss_cred, void *hold, ngx_log_t *log)
{
    (void) gss_cred; (void) hold; (void) log;
}

#endif
