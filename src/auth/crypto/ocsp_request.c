/*
 * OCSP request/response — build the query, POST it, and verify the reply.
 *
 * WHAT: The OCSP protocol crypto proper.  do_ocsp_request() builds an
 * OCSP_REQUEST (cert id + anti-replay nonce), opens/connects the responder BIO
 * via the transport layer, bounds every network phase under
 * BRIX_OCSP_TIMEOUT_SECS, POSTs the request, and returns the parsed
 * OCSP_RESPONSE.  check_ocsp_response() verifies that response — overall status,
 * responder signature against a trust store, nonce match — and maps the
 * certificate status to GOOD(0) / REVOKED(-1) / UNKNOWN(1).
 *
 * WHY: Split out of ocsp.c under the phase-79 file-size guard.  This file is the
 * security-critical heart of the revocation check: the nonce guards against
 * replay, the signature verification proves the response came from a trusted
 * responder, and the status mapping is the actual revocation decision.  Keeping
 * it separate from the URL/BIO transport (ocsp_transport.c) and the public entry
 * points (ocsp.c) keeps each concern reviewable in isolation.
 *
 * HOW: OCSP_request_add0_id() takes ownership of `id` on success (the caller
 * must not free it after a successful add).  do_ocsp_request() owns the BIO
 * teardown (ocsp_conn_free, cbio then ssl_ctx) and the request free on every
 * path.  check_ocsp_response() frees the BASICRESP on every path; a REVOKED
 * status is never overridden.  Shared structs/decls live in ocsp_internal.h.
 */

#include "ocsp_internal.h"

#include <openssl/ocsp.h>
#include <openssl/x509.h>

#include <stdio.h>

/*
 * ocsp_build_request — allocate an OCSP request for cert id `id` with a nonce.
 *
 * WHAT: Returns a new OCSP_REQUEST carrying `id` and a fresh nonce, or NULL on
 * allocation failure.
 * WHY: Splits request construction out of the network path so do_ocsp_request()
 * reads as build → connect → send.
 * HOW: OCSP_request_add0_id() takes ownership of `id` on success (unchanged
 * from the original — the caller must not free `id` after a successful add).
 * The nonce (OCSP_request_add1_nonce) guards against replay.  On the add0_id
 * failure path the half-built request is freed here.
 */
static OCSP_REQUEST *
ocsp_build_request(OCSP_CERTID *id)
{
    OCSP_REQUEST *req = OCSP_REQUEST_new();

    if (req == NULL) {
        return NULL;
    }
    if (OCSP_request_add0_id(req, id) == NULL) {
        OCSP_REQUEST_free(req);
        return NULL;
    }
    /* Add a nonce to prevent replay attacks */
    OCSP_request_add1_nonce(req, NULL, -1);
    return req;
}

/*
 * do_ocsp_request — build request, POST to responder, return parsed response.
 *
 * The caller must call OCSP_RESPONSE_free() on the returned pointer.
 * Returns NULL on any network or protocol error.
 */
/* HOW: Parses the OCSP URL via parse_ocsp_url() into an ocsp_url_t. Builds the OCSP_REQUEST (id + nonce) via ocsp_build_request(). Opens the responder BIO via ocsp_open_bio() (plain TCP or verifying TLS with SNI). Bounds the connect (ocsp_connect_bio) and, for HTTPS, the handshake+verify (ocsp_tls_handshake) under BRIX_OCSP_TIMEOUT_SECS. Sends the request and reads the reply through an OCSP_REQ_CTX whose response length is capped at OCSP_MAX_RESPONSE_BYTES (A-6/T2 — an untrusted responder must not stream an unbounded body), then tears down the connection (cbio then ssl_ctx) and the request. Returns NULL on any network/protocol failure or if the reply exceeds the cap. */
OCSP_RESPONSE *
do_ocsp_request(ngx_log_t *log, const char *url,
    X509 *leaf, X509 *issuer, OCSP_CERTID *id, OCSP_REQUEST **req_out)
{
    ocsp_url_t     u;
    char           hostport[320];
    OCSP_REQUEST  *req  = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_REQ_CTX  *rctx;
    int            rc;
    ocsp_conn_t    conn;

    *req_out = NULL;

    if (parse_ocsp_url(url, &u) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: cannot parse URL \"%s\"", url);
        return NULL;
    }

    req = ocsp_build_request(id);
    if (req == NULL) {
        return NULL;
    }

    /* Construct "host:port" for BIO */
    snprintf(hostport, sizeof(hostport), "%s:%d", u.host, u.port);

    if (ocsp_open_bio(log, &u, hostport, &conn) != 0) {
        OCSP_REQUEST_free(req);
        return NULL;
    }

    /* E1: bound the connect with a deadline (a black-holed responder must not
     * freeze the worker for the kernel TCP timeout). */
    if (ocsp_connect_bio(log, &conn, hostport) != 0) {
        ocsp_conn_free(&conn);
        OCSP_REQUEST_free(req);
        return NULL;
    }

    /* E1: bound the TLS handshake + request/response read/write phases. */
    ocsp_set_io_timeouts(conn.cbio, BRIX_OCSP_TIMEOUT_SECS);

    if (u.use_ssl
        && ocsp_tls_handshake(log, &conn, u.host, hostport) != 0)
    {
        ocsp_conn_free(&conn);
        OCSP_REQUEST_free(req);
        return NULL;
    }

    /* A2/T2: bound the response body.  The one-shot sendreq_bio helper reads
     * under only OpenSSL's internal default cap; drive the request context
     * ourselves so we pin the ceiling at OCSP_MAX_RESPONSE_BYTES — an untrusted
     * (and usually
     * plaintext/MITM-able) responder must not stream an unbounded body into the
     * worker.  Blocking BIO + SO_RCVTIMEO bound the wait; the -1 retry arm
     * covers a spurious BIO_should_retry. */
    rctx = OCSP_sendreq_new(conn.cbio, u.path, req, -1);
    if (rctx == NULL) {
        ocsp_conn_free(&conn);
        OCSP_REQUEST_free(req);
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: cannot build request context for \"%s\"", url);
        return NULL;
    }
    OCSP_set_max_response_length(rctx, OCSP_MAX_RESPONSE_BYTES);

    do {
        rc = OCSP_sendreq_nbio(&resp, rctx);
    } while (rc == -1 && BIO_should_retry(conn.cbio));

    OCSP_REQ_CTX_free(rctx);
    ocsp_conn_free(&conn);

    if (rc <= 0 || resp == NULL) {
        /* rc == 0 also fires when the reply exceeded OCSP_MAX_RESPONSE_BYTES:
         * OpenSSL aborts the read at the cap and returns failure. */
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: no valid response from \"%s\" (capped at %d bytes)",
                      url, OCSP_MAX_RESPONSE_BYTES);
        if (resp != NULL) {
            OCSP_RESPONSE_free(resp);
            resp = NULL;
        }
        OCSP_REQUEST_free(req);
        return NULL;
    }

    /* Success: hand the request (with its nonce) to the caller for the nonce
     * match; the caller owns it now and frees it after check_ocsp_response(). */
    *req_out = req;
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
/* HOW: Checks response status — returns -1 if not successful. Extracts the BASICRESP via OCSP_response_get1_basic(). Optionally verifies the response signature against a trust store (NULL means use OpenSSL defaults). If original request is available, checks nonce match — mismatch causes failure; missing nonce is a warning only. Finds certificate status via OCSP_resp_find_status() and maps to GOOD(0)/REVOKED(-1)/UNKNOWN(1) using a switch on the V_OCSP_CERTSTATUS_* enum. */
int
check_ocsp_response(ngx_log_t *log, OCSP_RESPONSE *resp,
    X509_STORE *store, OCSP_CERTID *id, OCSP_REQUEST *req_for_nonce,
    int require_nonce)
{
    OCSP_BASICRESP *bresp;
    int             status, reason;
    ASN1_GENERALIZEDTIME *rev = NULL, *thisupd = NULL, *nextupd = NULL;
    int             rc = -1;

    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: OCSP response status = %d (not successful)",
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
                      "brix_ocsp: OCSP response signature verification failed");
        OCSP_BASICRESP_free(bresp);
        return -1;
    }

    /* Check the nonce if we have the original request */
    if (req_for_nonce != NULL) {
        int nonce_rc = OCSP_check_nonce(req_for_nonce, bresp);
        if (nonce_rc < 0) {
            /* Nonce present in request but missing in response.  A missing nonce
             * lets an on-path attacker replay a captured (still-signed) GOOD
             * response.  Under brix_ocsp_require_nonce this is a hard failure
             * (A-6 item 2); otherwise warn only — most CA responders serve
             * pre-signed, nonce-less responses, so hard-fail is opt-in. */
            if (require_nonce) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "brix_ocsp: nonce missing in OCSP response and "
                              "brix_ocsp_require_nonce is on — denying (replay guard)");
                OCSP_BASICRESP_free(bresp);
                return -1;
            }
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_ocsp: nonce missing in OCSP response");
        } else if (nonce_rc == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_ocsp: OCSP response nonce mismatch");
            OCSP_BASICRESP_free(bresp);
            return -1;
        }
    }

    if (!OCSP_resp_find_status(bresp, id, &status, &reason,
                               &rev, &thisupd, &nextupd))
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: certificate not found in OCSP response");
        OCSP_BASICRESP_free(bresp);
        return -1;
    }

    switch (status) {
    case V_OCSP_CERTSTATUS_GOOD:
        rc = 0;
        break;
    case V_OCSP_CERTSTATUS_REVOKED:
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: certificate is REVOKED (reason=%d)", reason);
        rc = -1;
        break;
    case V_OCSP_CERTSTATUS_UNKNOWN:
    default:
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: certificate status is UNKNOWN");
        rc = 1;  /* caller decides based on soft_fail */
        break;
    }

    OCSP_BASICRESP_free(bresp);
    return rc;
}
