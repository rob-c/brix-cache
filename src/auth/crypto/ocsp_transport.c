/*
 * OCSP transport — responder URL parsing and deadline-bounded BIO connections.
 *
 * WHAT: Owns everything between "OCSP responder URL string" and "a connected,
 * verified BIO ready to POST on".  Provides parse_ocsp_url() (URL → ocsp_url_t),
 * ocsp_open_bio() (build a plain-TCP or verifying-TLS connect BIO),
 * ocsp_connect_bio() (drive the connect under BRIX_OCSP_TIMEOUT_SECS),
 * ocsp_set_io_timeouts() (bound the read/write phases), ocsp_tls_handshake()
 * (complete + verify the HTTPS handshake), and ocsp_conn_free() (fixed-order
 * teardown).
 *
 * WHY: Split out of ocsp.c under the phase-79 file-size guard.  Concentrating
 * the network/transport machinery here keeps ocsp_request.c focused on the OCSP
 * request/response crypto and ocsp.c on the public revocation/staple entry
 * points.  The per-phase deadlines (E1) are the reason a black-holed responder
 * cannot freeze the single-threaded worker event loop.
 *
 * HOW: The connect phase is bounded with a non-blocking connect + poll()
 * (SO_SNDTIMEO does not bound connect()); the handshake/read/write phases with
 * SO_RCVTIMEO/SO_SNDTIMEO.  ocsp_conn_t is the single owner of the BIO chain and
 * (HTTPS only) the SSL_CTX; every failure path cleans up in the original
 * BIO_free_all() → SSL_CTX_free() order.  The ssl handle is owned by the BIO
 * chain and is never freed separately.  Shared structs/decls live in
 * ocsp_internal.h.
 */

#include "ocsp_internal.h"
#include "observability/metrics/metrics.h"          /* ngx_brix_metrics_t */
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (E6): ocsp_timeouts_total */
#include "protocols/root/connection/netconnect.h"    /* shared SO_RCVTIMEO/SO_SNDTIMEO helper */

#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>

/* Apply SO_RCVTIMEO/SO_SNDTIMEO to the BIO's socket fd (best-effort). */
void
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
int
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
 * ocsp_conn_free — release a connection's OpenSSL objects in fixed order.
 *
 * WHAT: Frees the BIO chain, then the SSL_CTX (if any).
 * WHY: The BIO must be freed before the SSL_CTX it was built from; this mirrors
 * the original inline cleanup exactly to avoid leaks or double-frees.
 * HOW: BIO_free_all() tolerates NULL; ssl_ctx is guarded.  ssl is owned by the
 * BIO chain and must NOT be freed separately.
 */
void
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
int
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
int
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
int
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
