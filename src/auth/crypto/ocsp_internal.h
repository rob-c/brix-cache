#pragma once

/* Internal descriptors and cross-file entry points shared by the OCSP split
 * (ocsp.c / ocsp_transport.c / ocsp_request.c).
 *
 * WHAT: Declares the two file-local structs threaded through one OCSP fetch (the
 * parsed responder URL and the live OpenSSL connection objects), the shared
 * per-phase network timeout bound, and the seven functions that cross a
 * translation-unit boundary after the phase-79 file-size split: the URL parse,
 * the four BIO connection helpers (open / connect / io-timeouts / tls-handshake /
 * free), and the request/response pair (do_ocsp_request / check_ocsp_response).
 *
 * WHY: ocsp.c exceeded the ~500-line file-size guard, so it was carved into
 * three cohesive units. The URL/BIO transport (ocsp_transport.c) is called by
 * the request/response crypto (ocsp_request.c), which is in turn called by the
 * public revocation-check + staple-fetch entry points (ocsp.c). Grouping the
 * shared structs, the timeout constant, and the crossing entry points here keeps
 * every definition in exactly one place while preserving the identical request
 * nonce, signature verification, connect/handshake deadlines, and revocation
 * decisions of the original single-file implementation.
 *
 * HOW: Requires ocsp.h (ngx_log_t / ngx types / the public OCSP declarations)
 * before inclusion. ocsp_url_t is a fixed-capacity home for the host/path/port/
 * scheme of a parsed "http[s]://host[:port]/path" string; ocsp_conn_t bundles
 * the BIO chain and (HTTPS only) the SSL_CTX/SSL so a single owner tears them
 * down in the required BIO-then-CTX order. The transport helpers build/connect a
 * responder BIO; do_ocsp_request drives build → connect → send; and
 * check_ocsp_response verifies the response (status / signature / nonce) and
 * maps it to GOOD(0) / REVOKED(-1) / UNKNOWN(1). */

#include "ocsp.h"

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

/*
 * Phase 51 (E1): hard wall-clock bound (seconds) on every network phase of an
 * OCSP fetch — TCP connect, TLS handshake, and request/response.  Without this a
 * black-holed/slow responder blocks the single-threaded worker event loop for the
 * kernel TCP timeout (~60-120 s), freezing ALL connections.  The connect phase is
 * bounded with a non-blocking connect + poll() (SO_SNDTIMEO does not bound
 * connect()); the read/write phases with SO_RCVTIMEO/SO_SNDTIMEO.  On timeout the
 * fetch returns NULL and the caller applies its ocsp.soft_fail policy.
 */
#define BRIX_OCSP_TIMEOUT_SECS  5

/*
 * ocsp_url_t — parsed components of an OCSP responder URL.
 *
 * WHAT: Fixed-capacity home for the host, path, port, and scheme extracted
 * from an "http[s]://host[:port]/path" string, replacing a 7-parameter
 * out-argument signature with a single caller-owned struct.
 * WHY: Keeps parse_ocsp_url() at/under the 5-parameter budget and lets every
 * consumer carry one value instead of six loose locals — no behaviour change,
 * identical buffer capacities to the previous char[256]/char[512] locals.
 * HOW: The struct is stack-allocated by do_ocsp_request(); parse_ocsp_url()
 * fills it or reports failure.  host/path are NUL-terminated C strings.
 */
typedef struct {
    char  host[256];
    char  path[512];
    int   port;
    int   use_ssl;
} ocsp_url_t;

/*
 * ocsp_conn_t — live OpenSSL objects for one responder connection.
 *
 * WHAT: Holds the BIO chain and (for HTTPS) the SSL_CTX and its SSL handle so a
 * single owner can tear them all down in the exact required order.
 * WHY: The connect / handshake / send stages each need cbio (and ssl_ctx for
 * HTTPS); grouping them lets the builder return one value and lets
 * do_ocsp_request() keep sole ownership of cleanup — preserving the original
 * BIO_free_all() → SSL_CTX_free() ordering on every path.
 * HOW: ssl_ctx / ssl are NULL for plain HTTP.  ocsp_conn_free() frees cbio
 * first, then ssl_ctx, matching the pre-refactor teardown byte-for-byte.
 */
typedef struct {
    BIO      *cbio;
    SSL_CTX  *ssl_ctx;
    SSL      *ssl;
} ocsp_conn_t;

/* ---- Cross-translation-unit entry points (defined once, called across the split) ---- */

/* Defined in ocsp_transport.c — parse "http[s]://host[:port]/path" into an
 * ocsp_url_t.  Returns 0 on success, -1 on unsupported scheme / empty host. */
int parse_ocsp_url(const char *url, ocsp_url_t *out);

/* Defined in ocsp_transport.c — build the responder BIO for a parsed URL (plain
 * TCP or verifying TLS with SNI) and set its connect hostname to hostport.
 * Returns 0 on success (out populated), -1 on failure (out fully cleaned up). */
int ocsp_open_bio(ngx_log_t *log, const ocsp_url_t *u,
    const char *hostport, ocsp_conn_t *out);

/* Defined in ocsp_transport.c — drive the deadline-bounded connect on
 * conn->cbio; returns 0 on connect, -1 on failure/timeout (bumps the timeout
 * metric and logs on the sad paths).  Cleanup stays with the caller. */
int ocsp_connect_bio(ngx_log_t *log, ocsp_conn_t *conn, const char *hostport);

/* Defined in ocsp_transport.c — apply SO_RCVTIMEO/SO_SNDTIMEO to the BIO's
 * socket fd (best-effort) so the request/response phases cannot block forever. */
void ocsp_set_io_timeouts(BIO *cbio, int secs);

/* Defined in ocsp_transport.c — complete + verify the TLS handshake for an
 * HTTPS BIO (BIO_do_handshake + SSL_get_verify_result==X509_V_OK).  Returns 0 on
 * success, -1 on handshake or verification failure.  Cleanup stays with caller. */
int ocsp_tls_handshake(ngx_log_t *log, ocsp_conn_t *conn,
    const char *host, const char *hostport);

/* Defined in ocsp_transport.c — release a connection's OpenSSL objects in the
 * fixed BIO-then-CTX order (ssl is owned by the BIO chain, never freed here). */
void ocsp_conn_free(ocsp_conn_t *c);

/* Defined in ocsp_request.c — build the OCSP request (id + nonce), POST it to
 * the responder at url, and return the parsed response (caller frees via
 * OCSP_RESPONSE_free()).  Returns NULL on any network or protocol error. */
OCSP_RESPONSE *do_ocsp_request(ngx_log_t *log, const char *url,
    X509 *leaf, X509 *issuer, OCSP_CERTID *id);

/* Defined in ocsp_request.c — verify an OCSP response (status / signature vs
 * store / nonce vs req_for_nonce) and return the cert status: 0 GOOD, -1 REVOKED
 * or invalid, 1 UNKNOWN. */
int check_ocsp_response(ngx_log_t *log, OCSP_RESPONSE *resp,
    X509_STORE *store, OCSP_CERTID *id, OCSP_REQUEST *req_for_nonce);
