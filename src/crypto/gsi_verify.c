/*
 * gsi_verify.c — shared x.509 proxy chain verification core.
 *
 * Both the XRootD stream (GSI kXR_auth) and WebDAV (DAVS client certificate)
 * authentication paths perform identical X509_STORE_CTX setup and chain
 * verification.  Centralising here means any bug fix or security improvement
 * (flag addition, depth handling, error logging) automatically covers all
 * callers.
 *
 * WHAT: Wraps OpenSSL X509_STORE_CTX lifecycle — allocate, initialise with
 *       leaf + untrusted chain + CA store, set ALLOW_PROXY_CERTS flag,
 *       optionally set depth, call X509_verify_cert, extract leaf subject DN.
 *
 * WHY: The stream and WebDAV paths previously duplicated this ~25-line block
 *      verbatim.  A single defect (wrong flag, missing depth, wrong error
 *      logging) would affect only one path, causing inconsistent security
 *      behaviour between the two protocols.
 *
 * HOW: See xrootd_gsi_verify_chain() below.  The caller retains ownership of
 *      all passed-in objects; none are freed here.
 */

#include "gsi_verify.h"

#include <string.h>

/*
 * WHAT: Verify an x.509 proxy certificate chain against a CA trust store.
 *
 * HOW (step by step):
 *   1. Allocate a fresh X509_STORE_CTX (never reuse across requests).
 *   2. Initialise it: store = CA trust store, subject = leaf, untrusted = intermediates.
 *   3. Set X509_V_FLAG_ALLOW_PROXY_CERTS so proxy certificates (RFC 3820) in
 *      the chain are accepted — required for WLCG proxy credentials.
 *   4. Optionally set chain depth via X509_STORE_CTX_set_depth when the
 *      caller has a configured limit (verify_depth > 0).
 *   5. Call X509_verify_cert(); on failure extract the error code, log it, and
 *      return NGX_ERROR.
 *   6. On success extract the subject DN from the leaf via X509_NAME_oneline,
 *      copy to res->dn_buf (truncating safely if oversized), free the
 *      OpenSSL-allocated string, and return NGX_OK.
 */
ngx_int_t
xrootd_gsi_verify_chain(ngx_log_t *log, X509_STORE *store,
    X509 *leaf, STACK_OF(X509) *untrusted,
    ngx_uint_t verify_depth,
    xrootd_gsi_verify_result_t *res)
{
    X509_STORE_CTX *vctx;
    char           *dn_str;
    int             ok;

    ngx_memzero(res, sizeof(*res));

    vctx = X509_STORE_CTX_new();
    if (vctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: GSI: X509_STORE_CTX_new() failed");
        return NGX_ERROR;
    }

    if (!X509_STORE_CTX_init(vctx, store, leaf, untrusted)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: GSI: X509_STORE_CTX_init() failed");
        X509_STORE_CTX_free(vctx);
        return NGX_ERROR;
    }

    X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);

    if (verify_depth > 0) {
        X509_STORE_CTX_set_depth(vctx, (int) verify_depth);
    }

    ok = X509_verify_cert(vctx);
    if (!ok) {
        int         verr     = X509_STORE_CTX_get_error(vctx);
        const char *verr_str = X509_verify_cert_error_string(verr);

        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI cert verification failed: %s", verr_str);
        X509_STORE_CTX_free(vctx);
        return NGX_ERROR;
    }

    X509_STORE_CTX_free(vctx);

    dn_str = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    if (dn_str != NULL) {
        ngx_cpystrn((u_char *) res->dn_buf, (u_char *) dn_str,
                    sizeof(res->dn_buf));
        OPENSSL_free(dn_str);
    }

    return NGX_OK;
}
