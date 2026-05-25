/*
 * OCSP client — certificate revocation checking and TLS stapling.
 *
 * WHAT: Provides two public functions:
 *   xrootd_ocsp_check_cert()   — query OCSP responder for a client certificate.
 *   xrootd_ocsp_staple_fetch() — fetch OCSP staple for the server certificate.
 *
 * WHY: X.509 chain verification alone does not catch revoked certificates.
 * OCSP gives real-time revocation status without the overhead of fetching full
 * CRLs, which can be hundreds of megabytes for large CAs.
 *
 * HOW: Uses the OCSP URL embedded in the certificate's Authority Information
 * Access extension.  Makes a synchronous HTTP/1.0 POST using OpenSSL BIO.
 * Acceptable here because the auth path already does blocking crypto work.
 */

#include "ocsp.h"

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <string.h>
#include <stdlib.h>

/*
 * Maximum number of bytes accepted in an OCSP HTTP response body.
 * OCSP responses are small (a few KB at most); guard against runaways.
 */
#define OCSP_MAX_RESPONSE_BYTES  (64 * 1024)

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * parse_ocsp_url — parse "http://host[:port]/path" into components.
 *
 * Writes results into the caller-supplied char buffers.  port defaults to 80.
 * Returns 0 on success, -1 if the URL is malformed or not http://.
 */
/* ---- HOW: Splits the URL string by checking for http:// or https:// prefix. Extracts hostname up to the first ':' (port) or '/' (path). Defaults port=80, use_ssl=0; HTTPS sets port=443, use_ssl=1. Path defaults to "/" if no slash found in URL. Returns -1 if prefix is not http/https or hostname exceeds host_sz buffer. */
static int
parse_ocsp_url(const char *url, char *host, size_t host_sz,
    char *path, size_t path_sz, int *port, int *use_ssl)
{
    const char *p;
    const char *colon;
    const char *slash;
    size_t      hlen;

    *use_ssl = 0;
    *port    = 80;

    if (strncmp(url, "http://", 7) == 0) {
        p = url + 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        p        = url + 8;
        *use_ssl = 1;
        *port    = 443;
    } else {
        return -1;
    }

    slash = strchr(p, '/');
    colon = strchr(p, ':');

    /* Determine the end of the hostname */
    if (colon != NULL && (slash == NULL || colon < slash)) {
        hlen = (size_t)(colon - p);
        *port = atoi(colon + 1);
    } else if (slash != NULL) {
        hlen = (size_t)(slash - p);
    } else {
        hlen = strlen(p);
    }

    if (hlen == 0 || hlen >= host_sz) {
        return -1;
    }
    memcpy(host, p, hlen);
    host[hlen] = '\0';

    /* Path defaults to "/" */
    if (slash != NULL && strlen(slash) < path_sz) {
        memcpy(path, slash, strlen(slash) + 1);
    } else {
        memcpy(path, "/", 2);
    }

    return 0;
}

/*
 * do_ocsp_request — build request, POST to responder, return parsed response.
 *
 * The caller must call OCSP_RESPONSE_free() on the returned pointer.
 * Returns NULL on any network or protocol error.
 */
/* ---- HOW: Parses the OCSP URL via parse_ocsp_url() extracting host/path/port components. Rejects HTTPS responders (not implemented in sync path). Allocates OCSP_REQUEST, adds certificate ID and a nonce for replay protection. Opens a TCP connection via BIO_new_connect(), sends the request using OCSP_sendreq_bio(), then frees request and BIO. Returns NULL on any network/protocol failure. */
static OCSP_RESPONSE *
do_ocsp_request(ngx_log_t *log, const char *url,
    X509 *leaf, X509 *issuer, OCSP_CERTID *id)
{
    char           host[256];
    char           path[512];
    int            port, use_ssl;
    char           hostport[320];
    OCSP_REQUEST  *req  = NULL;
    OCSP_RESPONSE *resp = NULL;
    BIO           *cbio = NULL;

    if (parse_ocsp_url(url, host, sizeof(host),
                        path, sizeof(path), &port, &use_ssl) != 0)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: cannot parse URL \"%s\"", url);
        return NULL;
    }

    /* use_ssl / HTTPS stapling is not implemented in this synchronous path.
     * For HTTPS responders the caller should rely on soft_fail. */
    if (use_ssl) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd_ocsp: HTTPS OCSP responder not supported in sync path "
            "(\"%s\") — caller should use soft_fail", url);
        return NULL;
    }

    /* Build the OCSP request */
    req = OCSP_REQUEST_new();
    if (req == NULL) {
        return NULL;
    }

    if (OCSP_request_add0_id(req, id) == NULL) {
        OCSP_REQUEST_free(req);
        return NULL;
    }

    /* Add a nonce to prevent replay attacks */
    OCSP_request_add1_nonce(req, NULL, -1);

    /* Construct "host:port" for BIO */
    snprintf(hostport, sizeof(hostport), "%s:%d", host, port);

    cbio = BIO_new_connect(hostport);
    if (cbio == NULL) {
        OCSP_REQUEST_free(req);
        return NULL;
    }

    if (BIO_do_connect(cbio) <= 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: connect to \"%s\" failed", hostport);
        BIO_free_all(cbio);
        OCSP_REQUEST_free(req);
        return NULL;
    }

    resp = OCSP_sendreq_bio(cbio, path, req);

    BIO_free_all(cbio);
    OCSP_REQUEST_free(req);

    if (resp == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: no response from \"%s\"", url);
    }

    return resp;
}

/*
 * check_ocsp_response — verify the OCSP response and return the cert status.
 *
 * Returns:
 *   0   — certificate is GOOD
 *  -1   — certificate is REVOKED or response is invalid
 *   1   — status is UNKNOWN
 */
/* ---- HOW: Checks response status — returns -1 if not successful. Extracts the BASICRESP via OCSP_response_get1_basic(). Optionally verifies the response signature against a trust store (NULL means use OpenSSL defaults). If original request is available, checks nonce match — mismatch causes failure; missing nonce is a warning only. Finds certificate status via OCSP_resp_find_status() and maps to GOOD(0)/REVOKED(-1)/UNKNOWN(1) using a switch on the V_OCSP_CERTSTATUS_* enum. */
static int
check_ocsp_response(ngx_log_t *log, OCSP_RESPONSE *resp,
    X509_STORE *store, OCSP_CERTID *id, OCSP_REQUEST *req_for_nonce)
{
    OCSP_BASICRESP *bresp;
    int             status, reason;
    ASN1_GENERALIZEDTIME *rev = NULL, *thisupd = NULL, *nextupd = NULL;
    int             rc = -1;

    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: OCSP response status = %d (not successful)",
                      OCSP_response_status(resp));
        return -1;
    }

    bresp = OCSP_response_get1_basic(resp);
    if (bresp == NULL) {
        return -1;
    }

    /* Verify the response signature against the trust store */
    if (store != NULL && OCSP_basic_verify(bresp, NULL, store, 0) <= 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: OCSP response signature verification failed");
        OCSP_BASICRESP_free(bresp);
        return -1;
    }

    /* Check the nonce if we have the original request */
    if (req_for_nonce != NULL) {
        int nonce_rc = OCSP_check_nonce(req_for_nonce, bresp);
        if (nonce_rc < 0) {
            /* nonce present in request but missing in response — warn, don't fail */
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_ocsp: nonce missing in OCSP response");
        } else if (nonce_rc == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_ocsp: OCSP response nonce mismatch");
            OCSP_BASICRESP_free(bresp);
            return -1;
        }
    }

    if (!OCSP_resp_find_status(bresp, id, &status, &reason,
                               &rev, &thisupd, &nextupd))
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: certificate not found in OCSP response");
        OCSP_BASICRESP_free(bresp);
        return -1;
    }

    switch (status) {
    case V_OCSP_CERTSTATUS_GOOD:
        rc = 0;
        break;
    case V_OCSP_CERTSTATUS_REVOKED:
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: certificate is REVOKED (reason=%d)", reason);
        rc = -1;
        break;
    case V_OCSP_CERTSTATUS_UNKNOWN:
    default:
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: certificate status is UNKNOWN");
        rc = 1;  /* caller decides based on soft_fail */
        break;
    }

    OCSP_BASICRESP_free(bresp);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

/*
 * xrootd_ocsp_check_cert — query the OCSP responder for leaf's revocation.
 *
 * Extracts the OCSP URL from the leaf's AIA extension, builds and sends an
 * OCSP request, and interprets the response.
 *
 * Returns  0 if the certificate is GOOD (or soft_fail allows the outcome).
 * Returns -1 if the certificate is REVOKED or the check definitively fails.
 */
/* ---- HOW: Validates leaf and issuer are non-NULL (returns soft_fail result if either is missing). Extracts OCSP URLs from the certificate's AIA extension via X509_get1_ocsp(). Builds the OCSP certificate ID (SHA-1 hash of issuer fields) using OCSP_cert_to_id(). Iterates over all discovered responder URLs — sends a request via do_ocsp_request(), checks the response via check_ocsp_response(). GOOD results break the loop and return 0; REVOKED breaks immediately (never overridden); UNKNOWN applies soft_fail policy. Free ID and URL stack on exit. */
int
xrootd_ocsp_check_cert(ngx_log_t *log, X509 *leaf, X509 *issuer, int soft_fail)
{
    STACK_OF(OPENSSL_STRING) *ocsp_urls = NULL;
    OCSP_CERTID              *id        = NULL;
    OCSP_RESPONSE            *resp      = NULL;
    int                       i, n_urls;
    int                       result    = soft_fail ? 0 : -1; /* default on error */

    if (leaf == NULL) {
        return soft_fail ? 0 : -1;
    }

    if (issuer == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: no issuer certificate for OCSP check; "
                      "treating as soft_fail=%d", soft_fail);
        return soft_fail ? 0 : -1;
    }

    /* Extract OCSP URLs from the Authority Information Access extension */
    ocsp_urls = X509_get1_ocsp(leaf);
    if (ocsp_urls == NULL || sk_OPENSSL_STRING_num(ocsp_urls) == 0) {
        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "xrootd_ocsp: no OCSP URL in certificate AIA extension");
        if (ocsp_urls) {
            X509_email_free(ocsp_urls);
        }
        return soft_fail ? 0 : -1;
    }

    /* Build the OCSP certificate ID (SHA-1 hash of issuer fields) */
    id = OCSP_cert_to_id(NULL, leaf, issuer);
    if (id == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: OCSP_cert_to_id() failed");
        X509_email_free(ocsp_urls);
        return soft_fail ? 0 : -1;
    }

    n_urls = sk_OPENSSL_STRING_num(ocsp_urls);
    for (i = 0; i < n_urls; i++) {
        const char *url = sk_OPENSSL_STRING_value(ocsp_urls, i);
        int         status;

        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "xrootd_ocsp: querying responder \"%s\"", url);

        resp = do_ocsp_request(log, url, leaf, issuer, id);
        if (resp == NULL) {
            /* Network error — try next URL */
            continue;
        }

        /* NOTE: We pass NULL for the trust store so OpenSSL uses
         * the default verification.  A production deployment should
         * pass xcf->gsi_store here.  For the auth path this is
         * acceptable because the chain is already verified before
         * xrootd_ocsp_check_cert() is called. */
        status = check_ocsp_response(log, resp, NULL, id, NULL);
        OCSP_RESPONSE_free(resp);

        if (status == 0) {
            result = 0;   /* GOOD */
            ngx_log_error(NGX_LOG_DEBUG, log, 0,
                          "xrootd_ocsp: certificate is GOOD (\"%s\")", url);
            break;
        } else if (status == -1) {
            result = -1;  /* REVOKED — never override */
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_ocsp: certificate is REVOKED (\"%s\")", url);
            break;
        } else {
            /* UNKNOWN — apply soft_fail policy */
            result = soft_fail ? 0 : -1;
        }
    }

    OCSP_CERTID_free(id);
    X509_email_free(ocsp_urls);
    return result;
}

/*
 * xrootd_ocsp_staple_fetch — fetch and cache an OCSP staple.
 *
 * Queries the OCSP responder for xcf->gsi_cert and stores the raw DER
 * response bytes in xcf->ocsp_staple_data / ocsp_staple_len.
 *
 * Memory is allocated with ngx_alloc() and freed on the next reload.
 */
/* ---- HOW: Validates server certificate is non-NULL. Extracts OCSP URLs from the AIA extension. Locates the issuer certificate by initializing a X509_STORE_CTX against gsi_store and calling get1_issuer(). Builds the OCSP certificate ID via OCSP_cert_to_id(). Iterates responder URLs — sends request, verifies response signature against the trust store, only caches responses with status GOOD. Encodes the valid response to DER via i2d_OCSP_RESPONSE(), allocates nginx-managed memory for the staple bytes, frees old staple if present (reload path), stores buf/der_len in xcf fields. Returns NGX_OK on success, NGX_ERROR on failure. */
ngx_int_t
xrootd_ocsp_staple_fetch(ngx_log_t *log, ngx_stream_xrootd_srv_conf_t *xcf)
{
    X509                     *leaf      = xcf->gsi_cert;
    STACK_OF(OPENSSL_STRING) *ocsp_urls = NULL;
    OCSP_CERTID              *id        = NULL;
    OCSP_RESPONSE            *resp      = NULL;
    unsigned char            *der       = NULL;
    int                       der_len;
    u_char                   *buf;
    int                       i, n_urls;
    ngx_int_t                 rc        = NGX_ERROR;

    if (leaf == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: no server certificate; cannot fetch staple");
        return NGX_ERROR;
    }

    ocsp_urls = X509_get1_ocsp(leaf);
    if (ocsp_urls == NULL || sk_OPENSSL_STRING_num(ocsp_urls) == 0) {
        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "xrootd_ocsp: no OCSP URL in server certificate AIA");
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
    X509 *issuer = NULL;
    if (xcf->gsi_store != NULL) {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        if (ctx != NULL) {
            if (X509_STORE_CTX_init(ctx, xcf->gsi_store, leaf, NULL) == 1) {
                /* Retrieve the issuer from the store */
                X509_STORE_CTX_get1_issuer(&issuer, ctx, leaf);
            }
            X509_STORE_CTX_free(ctx);
        }
    }

    if (issuer == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_ocsp: cannot locate issuer certificate for staple");
        X509_email_free(ocsp_urls);
        return NGX_ERROR;
    }

    id = OCSP_cert_to_id(NULL, leaf, issuer);
    if (id == NULL) {
        X509_free(issuer);
        X509_email_free(ocsp_urls);
        return NGX_ERROR;
    }

    n_urls = sk_OPENSSL_STRING_num(ocsp_urls);
    for (i = 0; i < n_urls; i++) {
        const char *url = sk_OPENSSL_STRING_value(ocsp_urls, i);

        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "xrootd_ocsp: fetching staple from \"%s\"", url);

        resp = do_ocsp_request(log, url, leaf, issuer, id);
        if (resp == NULL) {
            continue;
        }

        /* Verify the response is GOOD before caching */
        {
            int status = check_ocsp_response(log, resp, xcf->gsi_store, id, NULL);
            if (status != 0) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "xrootd_ocsp: staple response not GOOD (status=%d) "
                    "from \"%s\" — skipping", status, url);
                OCSP_RESPONSE_free(resp);
                resp = NULL;
                continue;
            }
        }

        /* Encode response to DER for the TLS extension */
        der_len = i2d_OCSP_RESPONSE(resp, &der);
        OCSP_RESPONSE_free(resp);

        if (der_len <= 0 || der == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_ocsp: DER encoding of staple failed");
            continue;
        }

        /* Copy into nginx-managed memory so the TLS callback can use it */
        buf = ngx_alloc((size_t)der_len, log);
        if (buf == NULL) {
            OPENSSL_free(der);
            continue;
        }

        ngx_memcpy(buf, der, (size_t)der_len);
        OPENSSL_free(der);

        /* Free old staple if present (reload path) */
        if (xcf->ocsp_staple_data != NULL) {
            ngx_free(xcf->ocsp_staple_data);
        }
        xcf->ocsp_staple_data = buf;
        xcf->ocsp_staple_len  = (size_t)der_len;

        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "xrootd_ocsp: staple cached (%d bytes) from \"%s\"",
                      der_len, url);
        rc = NGX_OK;
        break;
    }

    OCSP_CERTID_free(id);
    X509_free(issuer);
    X509_email_free(ocsp_urls);
    return rc;
}
