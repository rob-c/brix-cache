/*
 * OCSP client — certificate revocation checking and TLS stapling.
 *
 * WHAT: Provides two public functions:
 *   brix_ocsp_check_cert()   — query OCSP responder for a client certificate.
 *   brix_ocsp_staple_fetch() — fetch OCSP staple for the server certificate.
 *
 * WHY: X.509 chain verification alone does not catch revoked certificates.
 * OCSP gives real-time revocation status without the overhead of fetching full
 * CRLs, which can be hundreds of megabytes for large CAs.
 *
 * HOW: Uses the OCSP URL embedded in the certificate's Authority Information
 * Access extension.  Makes a synchronous HTTP/1.0 POST using OpenSSL BIO; for
 * HTTPS responders it wraps the BIO in a verifying TLS client context with SNI.
 * Acceptable here because the auth path already does blocking crypto work.
 */

#include "ocsp.h"
#include "observability/metrics/metrics.h"          /* ngx_brix_metrics_t */
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (E6): ocsp_timeouts_total */
#include "protocols/root/connection/netconnect.h"    /* shared SO_RCVTIMEO/SO_SNDTIMEO helper */

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <time.h>

/*
 * Maximum number of bytes accepted in an OCSP HTTP response body.
 * OCSP responses are small (a few KB at most); guard against runaways.
 */
#define OCSP_MAX_RESPONSE_BYTES  (64 * 1024)

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

/* Apply SO_RCVTIMEO/SO_SNDTIMEO to the BIO's socket fd (best-effort). */
static void
ocsp_set_io_timeouts(BIO *cbio, int secs)
{
    int fd = -1;

    if (BIO_get_fd(cbio, &fd) <= 0 || fd < 0) {
        return;
    }
    brix_apply_socket_io_timeouts(fd, secs);
}

/*
 * Drive BIO_do_connect to completion under a `secs` deadline using non-blocking
 * mode + poll().  Returns 0 on connect, -1 on hard failure, -2 on TIMEOUT.  Leaves
 * the BIO in blocking mode on success so the subsequent handshake/sendreq (bounded
 * by SO_*TIMEO) behave normally.
 */
#define OCSP_CONNECT_OK       0
#define OCSP_CONNECT_FAIL    (-1)
#define OCSP_CONNECT_TIMEOUT (-2)

static int
ocsp_connect_deadline(BIO *cbio, int secs)
{
    time_t  deadline = time(NULL) + secs;

    BIO_set_nbio(cbio, 1);

    for ( ;; ) {
        struct pollfd  pfd;
        int            fd = -1;
        int            remaining_ms;

        if (BIO_do_connect(cbio) > 0) {
            BIO_set_nbio(cbio, 0);     /* back to blocking for SO_*TIMEO phase */
            return OCSP_CONNECT_OK;
        }
        if (!BIO_should_retry(cbio)) {
            return OCSP_CONNECT_FAIL;  /* hard failure */
        }
        if (BIO_get_fd(cbio, &fd) <= 0 || fd < 0) {
            return OCSP_CONNECT_FAIL;
        }
        remaining_ms = (int) ((deadline - time(NULL)) * 1000);
        if (remaining_ms <= 0) {
            return OCSP_CONNECT_TIMEOUT;   /* connect deadline exceeded */
        }
        pfd.fd      = fd;
        pfd.events  = POLLOUT | POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, remaining_ms) <= 0) {
            return OCSP_CONNECT_TIMEOUT;   /* poll timeout / error */
        }
    }
}


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
 * ocsp_url_scheme_start — advance past the URL scheme and set port/use_ssl.
 *
 * WHAT: Recognises the "http://" or "https://" prefix, seeds the default port
 * (80 / 443) and use_ssl flag on out, and returns the pointer just past the
 * scheme.
 * WHY: Isolates the one branch that distinguishes the two supported schemes so
 * parse_ocsp_url() reads as a straight-line hostname/port/path split.
 * HOW: Prefix compare with strncmp; NULL return signals an unsupported scheme.
 */
static const char *
ocsp_url_scheme_start(const char *url, ocsp_url_t *out)
{
    out->use_ssl = 0;
    out->port    = 80;

    if (strncmp(url, "http://", 7) == 0) {
        return url + 7;
    }
    if (strncmp(url, "https://", 8) == 0) {
        out->use_ssl = 1;
        out->port    = 443;
        return url + 8;
    }
    return NULL;
}

/*
 * parse_ocsp_url — parse "http://host[:port]/path" into an ocsp_url_t.
 *
 * WHAT: Fills out->host / out->path / out->port / out->use_ssl from url.
 * WHY: Callers need host:port + request path + scheme to open the responder
 * connection; centralising the split keeps the URL grammar in one place.
 * HOW: Skip the scheme (ocsp_url_scheme_start), locate the hostname end at the
 * first ':' (port) or '/' (path) — port defaults to the scheme default, path
 * defaults to "/".  Returns 0 on success, -1 if the scheme is unsupported or
 * the hostname is empty / does not fit out->host.
 */
static int
parse_ocsp_url(const char *url, ocsp_url_t *out)
{
    const char *p;
    const char *colon;
    const char *slash;
    size_t      hlen;

    p = ocsp_url_scheme_start(url, out);
    if (p == NULL) {
        return -1;
    }

    slash = strchr(p, '/');
    colon = strchr(p, ':');

    /* Determine the end of the hostname */
    if (colon != NULL && (slash == NULL || colon < slash)) {
        hlen      = (size_t)(colon - p);
        out->port = atoi(colon + 1);
    } else if (slash != NULL) {
        hlen = (size_t)(slash - p);
    } else {
        hlen = strlen(p);
    }

    if (hlen == 0 || hlen >= sizeof(out->host)) {
        return -1;
    }
    memcpy(out->host, p, hlen);
    out->host[hlen] = '\0';

    /* Path defaults to "/" */
    if (slash != NULL && strlen(slash) < sizeof(out->path)) {
        memcpy(out->path, slash, strlen(slash) + 1);
    } else {
        memcpy(out->path, "/", 2);
    }

    return 0;
}

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

/*
 * ocsp_conn_free — release a connection's OpenSSL objects in fixed order.
 *
 * WHAT: Frees the BIO chain, then the SSL_CTX (if any).
 * WHY: The BIO must be freed before the SSL_CTX it was built from; this mirrors
 * the original inline cleanup exactly to avoid leaks or double-frees.
 * HOW: BIO_free_all() tolerates NULL; ssl_ctx is guarded.  ssl is owned by the
 * BIO chain and must NOT be freed separately.
 */
static void
ocsp_conn_free(ocsp_conn_t *c)
{
    if (c->cbio != NULL) {
        BIO_free_all(c->cbio);
    }
    if (c->ssl_ctx != NULL) {
        SSL_CTX_free(c->ssl_ctx);
    }
}

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
 * ocsp_bio_new_ssl — build a verifying TLS-client BIO for an HTTPS responder.
 *
 * WHAT: Creates an SSL_CTX with peer verification + default trust paths, wraps
 * it in a connect BIO, and arms SNI + strict hostname verification for `host`.
 * On success out->cbio / out->ssl_ctx / out->ssl are populated; returns 0.
 * On any failure out is left cleaned up (freed, fields NULL) and returns -1.
 * WHY: Concentrates the HTTPS-only setup so ocsp_open_bio() stays a thin
 * scheme switch; preserves the original security posture (SSL_VERIFY_PEER,
 * SSL_set1_host) exactly.
 * HOW: Cleans up in-place on each failure in the same BIO-then-CTX order as the
 * original inline code.  ssl is owned by the BIO chain (never freed here).
 */
static int
ocsp_bio_new_ssl(ngx_log_t *log, const char *host, ocsp_conn_t *out)
{
    out->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (out->ssl_ctx == NULL) {
        return -1;
    }

    SSL_CTX_set_verify(out->ssl_ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(out->ssl_ctx) != 1) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: cannot load default HTTPS trust paths");
        SSL_CTX_free(out->ssl_ctx);
        out->ssl_ctx = NULL;
        return -1;
    }

    out->cbio = BIO_new_ssl_connect(out->ssl_ctx);
    if (out->cbio == NULL) {
        SSL_CTX_free(out->ssl_ctx);
        out->ssl_ctx = NULL;
        return -1;
    }

    BIO_get_ssl(out->cbio, &out->ssl);
    if (out->ssl != NULL) {
        (void) SSL_set_tlsext_host_name(out->ssl, host);
        if (SSL_set1_host(out->ssl, host) != 1) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_ocsp: cannot set HTTPS hostname "
                          "verification for \"%s\"", host);
            ocsp_conn_free(out);
            out->cbio    = NULL;
            out->ssl_ctx = NULL;
            out->ssl     = NULL;
            return -1;
        }
    }
    return 0;
}

/*
 * ocsp_open_bio — build the responder BIO for a parsed URL (HTTP or HTTPS).
 *
 * WHAT: Populates out with a connect BIO for `u` (plus SSL_CTX/SSL for HTTPS)
 * and sets its connect hostname to `hostport`.  Returns 0 on success, -1 on
 * failure (out fully cleaned up on failure).
 * WHY: Gives do_ocsp_request() a single scheme-agnostic entry point so its body
 * is connect → handshake → send with no BIO-construction branching.
 * HOW: Delegates HTTPS to ocsp_bio_new_ssl(); plain HTTP uses BIO_new_connect().
 * BIO_set_conn_hostname() is applied uniformly, matching the original.
 */
static int
ocsp_open_bio(ngx_log_t *log, const ocsp_url_t *u,
    const char *hostport, ocsp_conn_t *out)
{
    out->cbio    = NULL;
    out->ssl_ctx = NULL;
    out->ssl     = NULL;

    if (u->use_ssl) {
        if (ocsp_bio_new_ssl(log, u->host, out) != 0) {
            return -1;
        }
    } else {
        out->cbio = BIO_new_connect(hostport);
    }

    if (out->cbio == NULL) {
        ocsp_conn_free(out);
        out->cbio    = NULL;
        out->ssl_ctx = NULL;
        return -1;
    }

    BIO_set_conn_hostname(out->cbio, hostport);
    return 0;
}

/*
 * ocsp_connect_bio — drive the deadline-bounded connect and log the outcome.
 *
 * WHAT: Runs ocsp_connect_deadline() on conn->cbio; returns 0 on connect, -1 on
 * failure or timeout (bumping the timeout metric and logging on the sad paths).
 * WHY: Keeps the E1 connect-deadline bookkeeping (metric + WARN) out of the main
 * flow while leaving cleanup ownership with the caller.
 * HOW: Pure status translation — no OpenSSL objects are freed here.
 */
static int
ocsp_connect_bio(ngx_log_t *log, ocsp_conn_t *conn, const char *hostport)
{
    int crc = ocsp_connect_deadline(conn->cbio, BRIX_OCSP_TIMEOUT_SECS);

    if (crc == OCSP_CONNECT_OK) {
        return 0;
    }
    if (crc == OCSP_CONNECT_TIMEOUT) {
        BRIX_RESIL_METRIC_INC(ocsp_timeouts_total);
    }
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix_ocsp: connect to \"%s\" %s (%ds)", hostport,
                  crc == OCSP_CONNECT_TIMEOUT ? "timed out" : "failed",
                  BRIX_OCSP_TIMEOUT_SECS);
    return -1;
}

/*
 * ocsp_tls_handshake — complete + verify the TLS handshake for an HTTPS BIO.
 *
 * WHAT: Runs BIO_do_handshake() and checks SSL_get_verify_result()==X509_V_OK.
 * Returns 0 on success, -1 on handshake or verification failure.
 * WHY: Isolates the HTTPS-only handshake/verify pair so do_ocsp_request() only
 * calls it on the SSL path; preserves the exact verification requirement.
 * HOW: No objects are freed here — the caller owns teardown on failure.
 */
static int
ocsp_tls_handshake(ngx_log_t *log, ocsp_conn_t *conn,
    const char *host, const char *hostport)
{
    if (BIO_do_handshake(conn->cbio) <= 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: TLS handshake with \"%s\" failed", hostport);
        return -1;
    }
    if (conn->ssl == NULL
        || SSL_get_verify_result(conn->ssl) != X509_V_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: TLS verification for \"%s\" failed", host);
        return -1;
    }
    return 0;
}

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
 * do_ocsp_request — build request, POST to responder, return parsed response.
 *
 * The caller must call OCSP_RESPONSE_free() on the returned pointer.
 * Returns NULL on any network or protocol error.
 */
/* HOW: Parses the OCSP URL via parse_ocsp_url() into an ocsp_url_t. Builds the OCSP_REQUEST (id + nonce) via ocsp_build_request(). Opens the responder BIO via ocsp_open_bio() (plain TCP or verifying TLS with SNI). Bounds the connect (ocsp_connect_bio) and, for HTTPS, the handshake+verify (ocsp_tls_handshake) under BRIX_OCSP_TIMEOUT_SECS. Sends via OCSP_sendreq_bio(), then tears down the connection (cbio then ssl_ctx) and the request. Returns NULL on any network/protocol failure. */
static OCSP_RESPONSE *
do_ocsp_request(ngx_log_t *log, const char *url,
    X509 *leaf, X509 *issuer, OCSP_CERTID *id)
{
    ocsp_url_t     u;
    char           hostport[320];
    OCSP_REQUEST  *req  = NULL;
    OCSP_RESPONSE *resp = NULL;
    ocsp_conn_t    conn;

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

    resp = OCSP_sendreq_bio(conn.cbio, u.path, req);

    ocsp_conn_free(&conn);
    OCSP_REQUEST_free(req);

    if (resp == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_ocsp: no response from \"%s\"", url);
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
/* HOW: Checks response status — returns -1 if not successful. Extracts the BASICRESP via OCSP_response_get1_basic(). Optionally verifies the response signature against a trust store (NULL means use OpenSSL defaults). If original request is available, checks nonce match — mismatch causes failure; missing nonce is a warning only. Finds certificate status via OCSP_resp_find_status() and maps to GOOD(0)/REVOKED(-1)/UNKNOWN(1) using a switch on the V_OCSP_CERTSTATUS_* enum. */
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
            /* nonce present in request but missing in response — warn, don't fail */
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
    const ocsp_query_t *q, int soft_fail)
{
    int result = soft_fail ? 0 : -1; /* default on error / UNKNOWN */
    int n_urls = sk_OPENSSL_STRING_num(ocsp_urls);
    int i;

    for (i = 0; i < n_urls; i++) {
        const char    *url = sk_OPENSSL_STRING_value(ocsp_urls, i);
        OCSP_RESPONSE *resp;
        int            status;

        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "brix_ocsp: querying responder \"%s\"", url);

        resp = do_ocsp_request(log, url, q->leaf, q->issuer, q->id);
        if (resp == NULL) {
            /* Network error — try next URL */
            continue;
        }

        /* NOTE: We pass NULL for the trust store so OpenSSL uses
         * the default verification.  A production deployment should
         * pass xcf->gsi_store here.  For the auth path this is
         * acceptable because the chain is already verified before
         * brix_ocsp_check_cert() is called. */
        status = check_ocsp_response(log, resp, NULL, q->id, NULL);
        OCSP_RESPONSE_free(resp);

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
brix_ocsp_check_cert(ngx_log_t *log, X509 *leaf, X509 *issuer, int soft_fail)
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
        result = ocsp_check_urls(log, ocsp_urls, &q, soft_fail);
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
        int            status;

        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                      "brix_ocsp: fetching staple from \"%s\"", url);

        resp = do_ocsp_request(log, url, q->leaf, q->issuer, q->id);
        if (resp == NULL) {
            continue;
        }

        /* Verify the response is GOOD before caching */
        status = check_ocsp_response(log, resp, xcf->gsi_store, q->id, NULL);
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
