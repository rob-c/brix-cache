/*
 * OCSP client — public revocation-check and TLS-staple entry points.
 *
 * WHAT: Provides the two public functions:
 *   brix_ocsp_check_cert()   — query OCSP responder for a client certificate.
 *   brix_ocsp_staple_fetch() — fetch OCSP staple for the server certificate.
 * Each extracts the responder URLs from the certificate's Authority Information
 * Access extension, builds the OCSP cert id, drives the per-URL query loop, and
 * interprets / caches the result.
 *
 * WHY: X.509 chain verification alone does not catch revoked certificates.
 * OCSP gives real-time revocation status without the overhead of fetching full
 * CRLs, which can be hundreds of megabytes for large CAs.  This file owns the
 * public policy: which URLs to try, how soft_fail maps network errors / UNKNOWN,
 * that REVOKED is never overridden, and how a GOOD staple is DER-cached on xcf.
 *
 * HOW: The URL/BIO transport (parse + connect + handshake) lives in
 * ocsp_transport.c and the OCSP request/response crypto (nonce, signature
 * verify, status mapping) in ocsp_request.c — both split out under the phase-79
 * file-size guard and shared through ocsp_internal.h.  This file calls
 * do_ocsp_request() + check_ocsp_response() in a loop over the AIA URLs and
 * applies the soft_fail / staple-caching policy on top.  The synchronous
 * blocking model is acceptable because the auth path already performs blocking
 * crypto work.
 */

#include "ocsp.h"
#include "ocsp_internal.h"

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>
#include <stdlib.h>

/* OCSP_MAX_RESPONSE_BYTES now lives in ocsp_internal.h (enforced by the
 * transport read in ocsp_request.c, not just defined). */

/*
 * ocsp_query_t — the certificate identity for one OCSP query.
 *
 * WHAT: Bundles the leaf, its issuer, and the derived OCSP_CERTID that always
 * travel together from the AIA-URL loop down into do_ocsp_request().
 * WHY: Keeps the URL-loop helpers at/under the 5-parameter budget by passing
 * one identity value instead of three loose pointers — no behaviour change; the
 * struct is a non-owning view (the caller still owns/free()s each member).
 * HOW: Stack-allocated in the public functions; passed by const pointer.
 */
typedef struct {
    X509         *leaf;
    X509         *issuer;
    OCSP_CERTID  *id;
} ocsp_query_t;

/*
 * brix_ocsp_check_cert — query the OCSP responder for leaf's revocation.
 *
 * Extracts the OCSP URL from the leaf's AIA extension, builds and sends an
 * OCSP request, and interprets the response.
 *
 * Returns  0 if the certificate is GOOD (or soft_fail allows the outcome).
 * Returns -1 if the certificate is REVOKED or the check definitively fails.
 */
/*
 * ocsp_check_urls — query each responder URL until a definitive answer.
 *
 * WHAT: Iterates the AIA responder URLs, sending an OCSP request for `id` and
 * interpreting the reply, and returns the check result: 0 (GOOD), -1 (REVOKED
 * or hard fail), or the soft_fail default for network errors / UNKNOWN.
 * WHY: Factors the multi-URL loop out of brix_ocsp_check_cert() so the public
 * function is validate-inputs → build-id → loop → free, keeping each part
 * small; behaviour (GOOD/REVOKED break semantics, soft_fail fallback) is
 * preserved exactly.
 * HOW: GOOD returns 0 immediately; REVOKED returns -1 immediately (never
 * overridden); UNKNOWN and network errors leave the running soft_fail default,
 * which is returned once the URLs are exhausted.  The trust store is NULL by
 * design (chain already verified before this call — see the note below).
 */
static int
ocsp_check_urls(ngx_log_t *log, STACK_OF(OPENSSL_STRING) *ocsp_urls,
    const ocsp_query_t *q, int soft_fail, int require_nonce)
{
    int result = soft_fail ? 0 : -1; /* default on error / UNKNOWN */
    int n_urls = sk_OPENSSL_STRING_num(ocsp_urls);
    int i;

    for (i = 0; i < n_urls; i++) {
        const char    *url = sk_OPENSSL_STRING_value(ocsp_urls, i);
        OCSP_RESPONSE *resp;
        OCSP_REQUEST  *req = NULL;
        int            status;

        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "brix_ocsp: querying responder \"%s\"", url);

        resp = do_ocsp_request(log, url, q->leaf, q->issuer, q->id, &req);
        if (resp == NULL) {
            /* Network error — try next URL */
            continue;
        }

        /* NOTE: We pass NULL for the trust store so OpenSSL uses
         * the default verification.  A production deployment should
         * pass xcf->gsi_store here.  For the auth path this is
         * acceptable because the chain is already verified before
         * brix_ocsp_check_cert() is called.  `req` carries the nonce so the
         * response's nonce can be matched (and, under require_nonce, enforced). */
        status = check_ocsp_response(log, resp, NULL, q->id, req, require_nonce);
        OCSP_RESPONSE_free(resp);
        OCSP_REQUEST_free(req);

        if (status == 0) {
            ngx_log_error(NGX_LOG_DEBUG, log, 0,
                          "brix_ocsp: certificate is GOOD (\"%s\")", url);
            return 0;   /* GOOD */
        }
        if (status == -1) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_ocsp: certificate is REVOKED (\"%s\")", url);
            return -1;  /* REVOKED — never override */
        }
        /* UNKNOWN — apply soft_fail policy and keep trying other URLs */
        result = soft_fail ? 0 : -1;
    }

    return result;
}

/* HOW: Validates leaf and issuer are non-NULL (returns soft_fail result if either is missing). Extracts OCSP URLs from the certificate's AIA extension via X509_get1_ocsp(). Builds the OCSP certificate ID (SHA-1 hash of issuer fields) using OCSP_cert_to_id(). Delegates the per-URL query loop to ocsp_check_urls() (GOOD→0, REVOKED→-1 never overridden, UNKNOWN/network-error→soft_fail default). Frees ID and URL stack on exit. */
int
brix_ocsp_check_cert(ngx_log_t *log, X509 *leaf, X509 *issuer, int soft_fail,
    int require_nonce)
{
    STACK_OF(OPENSSL_STRING) *ocsp_urls = NULL;
    OCSP_CERTID              *id        = NULL;
    int                       result;

    if (leaf == NULL) {
        return soft_fail ? 0 : -1;
    }

    if (issuer == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: no issuer certificate for OCSP check; "
                      "treating as soft_fail=%d", soft_fail);
        return soft_fail ? 0 : -1;
    }

    /* Extract OCSP URLs from the Authority Information Access extension */
    ocsp_urls = X509_get1_ocsp(leaf);
    if (ocsp_urls == NULL || sk_OPENSSL_STRING_num(ocsp_urls) == 0) {
        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "brix_ocsp: no OCSP URL in certificate AIA extension");
        if (ocsp_urls) {
            X509_email_free(ocsp_urls);
        }
        return soft_fail ? 0 : -1;
    }

    /* Build the OCSP certificate ID (SHA-1 hash of issuer fields) */
    id = OCSP_cert_to_id(NULL, leaf, issuer);
    if (id == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: OCSP_cert_to_id() failed");
        X509_email_free(ocsp_urls);
        return soft_fail ? 0 : -1;
    }

    {
        ocsp_query_t q = { leaf, issuer, id };
        result = ocsp_check_urls(log, ocsp_urls, &q, soft_fail, require_nonce);
    }

    OCSP_CERTID_free(id);
    X509_email_free(ocsp_urls);
    return result;
}

/*
 * brix_ocsp_staple_fetch — fetch and cache an OCSP staple.
 *
 * Queries the OCSP responder for xcf->gsi_cert and stores the raw DER
 * response bytes in xcf->ocsp.staple_data / ocsp.staple_len.
 *
 * Memory is allocated with ngx_alloc() and freed on the next reload.
 */
/*
 * ocsp_find_issuer — locate leaf's issuer certificate in the CA trust store.
 *
 * WHAT: Returns the issuer of `leaf` found in `store` (caller owns the ref via
 * X509_free), or NULL if the store is absent or the issuer is not found.
 * WHY: The staple's OCSP request needs the issuer; isolating the store-context
 * dance keeps brix_ocsp_staple_fetch() readable and its cleanup unambiguous.
 * HOW: X509_STORE_CTX_get1_issuer() bumps the returned cert's refcount, so the
 * caller must X509_free() it — identical ownership to the original inline code.
 */
static X509 *
ocsp_find_issuer(X509_STORE *store, X509 *leaf)
{
    X509           *issuer = NULL;
    X509_STORE_CTX *ctx;

    if (store == NULL) {
        return NULL;
    }
    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        return NULL;
    }
    if (X509_STORE_CTX_init(ctx, store, leaf, NULL) == 1) {
        /* Retrieve the issuer from the store (refcounted) */
        X509_STORE_CTX_get1_issuer(&issuer, ctx, leaf);
    }
    X509_STORE_CTX_free(ctx);
    return issuer;
}

/*
 * ocsp_store_staple — DER-encode a GOOD response and cache it on xcf.
 *
 * WHAT: Encodes `resp` to DER, copies it into nginx-managed memory, replaces
 * any previously cached staple, and records buf/len on xcf->ocsp.  Returns
 * NGX_OK on success, NGX_ERROR if encoding or allocation fails.
 * WHY: Concentrates the encode → copy → swap sequence (and its OPENSSL_free /
 * ngx_free ordering) so the fetch loop stays a thin driver.
 * HOW: i2d_OCSP_RESPONSE() allocates `der` via OPENSSL_free-owned memory; it is
 * always released here.  The old staple is freed only after the new buffer is
 * in hand, matching the original reload path exactly.
 */
static ngx_int_t
ocsp_store_staple(ngx_log_t *log, ngx_stream_brix_srv_conf_t *xcf,
    OCSP_RESPONSE *resp, const char *url)
{
    unsigned char *der = NULL;
    int            der_len;
    u_char        *buf;

    /* Encode response to DER for the TLS extension */
    der_len = i2d_OCSP_RESPONSE(resp, &der);
    if (der_len <= 0 || der == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: DER encoding of staple failed");
        return NGX_ERROR;
    }

    /* Copy into nginx-managed memory so the TLS callback can use it */
    buf = ngx_alloc((size_t)der_len, log);
    if (buf == NULL) {
        OPENSSL_free(der);
        return NGX_ERROR;
    }

    ngx_memcpy(buf, der, (size_t)der_len);
    OPENSSL_free(der);

    /* Free old staple if present (reload path) */
    if (xcf->ocsp.staple_data != NULL) {
        ngx_free(xcf->ocsp.staple_data);
    }
    xcf->ocsp.staple_data = buf;
    xcf->ocsp.staple_len  = (size_t)der_len;

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "brix_ocsp: staple cached (%d bytes) from \"%s\"",
                  der_len, url);
    return NGX_OK;
}

/*
 * ocsp_fetch_staple_urls — query responders until one yields a cacheable staple.
 *
 * WHAT: Iterates the AIA URLs; for each, fetches the OCSP response, requires a
 * GOOD verified status (against xcf->gsi_store), and on success caches it via
 * ocsp_store_staple().  Returns NGX_OK once a staple is cached, else NGX_ERROR.
 * WHY: Splits the per-URL loop out of brix_ocsp_staple_fetch() so the public
 * function is validate → find-issuer → build-id → loop → free.
 * HOW: Each response is freed on every path (skip / cache).  Only GOOD (status
 * 0) responses are cached, preserving the original "not GOOD → skip" policy.
 */
static ngx_int_t
ocsp_fetch_staple_urls(ngx_log_t *log, ngx_stream_brix_srv_conf_t *xcf,
    STACK_OF(OPENSSL_STRING) *ocsp_urls, const ocsp_query_t *q)
{
    int n_urls = sk_OPENSSL_STRING_num(ocsp_urls);
    int i;

    for (i = 0; i < n_urls; i++) {
        const char    *url = sk_OPENSSL_STRING_value(ocsp_urls, i);
        OCSP_RESPONSE *resp;
        OCSP_REQUEST  *req = NULL;
        int            status;

        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "brix_ocsp: fetching staple from \"%s\"", url);

        resp = do_ocsp_request(log, url, q->leaf, q->issuer, q->id, &req);
        if (resp == NULL) {
            continue;
        }

        /* Verify the response is GOOD before caching.  Staple prefetch is a
         * server-side cache warm, not a live client decision, so the nonce is
         * matched-if-present but never required (require_nonce = 0). */
        status = check_ocsp_response(log, resp, xcf->gsi_store, q->id, req, 0);
        OCSP_REQUEST_free(req);
        req = NULL;
        if (status != 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "brix_ocsp: staple response not GOOD (status=%d) "
                "from \"%s\" — skipping", status, url);
            OCSP_RESPONSE_free(resp);
            continue;
        }

        if (ocsp_store_staple(log, xcf, resp, url) != NGX_OK) {
            OCSP_RESPONSE_free(resp);
            continue;
        }
        OCSP_RESPONSE_free(resp);
        return NGX_OK;
    }

    return NGX_ERROR;
}

/* HOW: Validates server certificate is non-NULL. Extracts OCSP URLs from the AIA extension. Locates the issuer certificate via ocsp_find_issuer() (X509_STORE_CTX against gsi_store). Builds the OCSP certificate ID via OCSP_cert_to_id(). Delegates the per-URL fetch/verify/cache loop to ocsp_fetch_staple_urls() (only GOOD responses cached, DER-encoded into nginx memory, old staple freed on the reload path). Returns NGX_OK once a staple is cached, NGX_ERROR otherwise. Frees ID, issuer, and URL stack on exit. */
ngx_int_t
brix_ocsp_staple_fetch(ngx_log_t *log, ngx_stream_brix_srv_conf_t *xcf)
{
    X509                     *leaf      = xcf->gsi_cert;
    X509                     *issuer    = NULL;
    STACK_OF(OPENSSL_STRING) *ocsp_urls = NULL;
    OCSP_CERTID              *id        = NULL;
    ngx_int_t                 rc;

    if (leaf == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: no server certificate; cannot fetch staple");
        return NGX_ERROR;
    }

    ocsp_urls = X509_get1_ocsp(leaf);
    if (ocsp_urls == NULL || sk_OPENSSL_STRING_num(ocsp_urls) == 0) {
        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "brix_ocsp: no OCSP URL in server certificate AIA");
        if (ocsp_urls) {
            X509_email_free(ocsp_urls);
        }
        return NGX_ERROR;
    }

    /*
     * For the staple we need the issuer certificate.  Attempt to find it
     * in the configured CA trust store (gsi_store).  If not available,
     * we cannot produce a staple — log and return.
     */
    issuer = ocsp_find_issuer(xcf->gsi_store, leaf);
    if (issuer == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: cannot locate issuer certificate for staple");
        X509_email_free(ocsp_urls);
        return NGX_ERROR;
    }

    id = OCSP_cert_to_id(NULL, leaf, issuer);
    if (id == NULL) {
        X509_free(issuer);
        X509_email_free(ocsp_urls);
        return NGX_ERROR;
    }

    {
        ocsp_query_t q = { leaf, issuer, id };
        rc = ocsp_fetch_staple_urls(log, xcf, ocsp_urls, &q);
    }

    OCSP_CERTID_free(id);
    X509_free(issuer);
    X509_email_free(ocsp_urls);
    return rc;
}
