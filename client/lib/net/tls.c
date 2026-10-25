/*
 * tls.c — in-protocol TLS for the native client (roots:// and GSI+TLS).
 *
 * WHAT: Upgrade the live socket to a TLS session (after the kXR_protocol reply,
 *       before kXR_login) and transfer bytes transparently through it. Server
 *       certificate verification against a CA hash dir ($X509_CERT_DIR) is on by
 *       default; a name-check escape (--noverifyhost) relaxes only the hostname.
 * WHY:  XRootD encrypts the control/data stream in-protocol; the same SSL session
 *       then carries login, GSI auth, and all file ops.
 * HOW:  The fd goes non-blocking at upgrade time; SSL_connect and the read/write
 *       loops drive OpenSSL's WANT_READ/WANT_WRITE through the same poll(2) +
 *       timeout discipline the cleartext path uses. sock.c branches to these when
 *       io->ssl != NULL, so no other file changes for TLS. Byte transfer itself
 *       lives in tls_io.c, split out when this file crossed the 600-line cap; the
 *       two helpers both halves need are declared in tls_internal.h.
 */
#include "brix.h"
#include "tls_internal.h"
#include "auth/crypto/tls_compat.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void
brix_tls_err(brix_status *st, int kxr, const char *what)
{
    unsigned long e = ERR_get_error();
    char          buf[256];

    if (e != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
    } else {
        buf[0] = '\0';
    }
    brix_status_set(st, kxr, 0, "%s: %s", what, buf[0] ? buf : "TLS error");
}

/* poll one fd for `events`; >0 ready, 0 timeout, <0 error (EINTR retried). */
int
brix_tls_wait_io(int fd, short events, int timeout_ms)
{
    struct pollfd pfd;
    int           pr;

    pfd.fd = fd;
    pfd.events = events;
    do {
        pr = poll(&pfd, 1, timeout_ms);
    } while (pr < 0 && errno == EINTR && !brix_copy_quit_requested());
    return pr;
}


/* Drive a non-blocking SSL_connect to completion (poll on WANT_*). 0 / -1. */
static int
tls_do_connect(SSL *ssl, brix_io *io, int verify_peer, brix_status *st)
{
    for (;;) {
        int ret, err;

        ERR_clear_error();
        ret = SSL_connect(ssl);
        if (ret == 1) {
            break;
        }
        err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            short ev = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if (brix_tls_wait_io(io->fd, ev, io->timeout_ms) <= 0) {
                brix_status_set(st, XRDC_ESOCK, 0, "TLS handshake timed out");
                return -1;
            }
            continue;
        }
        {
            long vr = SSL_get_verify_result(ssl);
            if (vr != X509_V_OK) {
                brix_status_set(st, XRDC_EAUTH, 0, "TLS verify failed: %s",
                                X509_verify_cert_error_string(vr));
            } else {
                brix_tls_err(st, XRDC_ESOCK, "SSL_connect");
            }
        }
        return -1;
    }

    if (verify_peer) {
        long vr = SSL_get_verify_result(ssl);
        if (vr != X509_V_OK) {
            brix_status_set(st, XRDC_EAUTH, 0, "TLS verify failed: %s",
                            X509_verify_cert_error_string(vr));
            return -1;
        }
    }
    return 0;
}

static SSL_CTX *
tls_upgrade_ctx(const brix_conn *c, int verify_peer, const char *ca_dir,
    brix_status *st)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL) {
        brix_tls_err(st, XRDC_ESOCK, "SSL_CTX_new");
        return NULL;
    }
    if (c->opts.tls_max_version != 0) {
        SSL_CTX_set_security_level(ctx, 0);
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        SSL_CTX_set_max_proto_version(ctx, c->opts.tls_max_version);
    } else {
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    }
    if (!verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        return ctx;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (ca_dir != NULL && ca_dir[0] != '\0') {
        if (SSL_CTX_load_verify_locations(ctx, NULL, ca_dir) != 1) {
            brix_tls_err(st, XRDC_EAUTH, "load CA dir");
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        SSL_CTX_set_default_verify_paths(ctx);
    }
    X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx),
                                X509_V_FLAG_ALLOW_PROXY_CERTS);
    return ctx;
}

int
brix_tls_upgrade(brix_conn *c, int verify_peer, int verify_host,
                 const char *ca_dir, brix_status *st)
{
    SSL_CTX *ctx;
    SSL     *ssl;
    int      fl;

    ctx = tls_upgrade_ctx(c, verify_peer, ca_dir, st);
    if (ctx == NULL) {
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        brix_tls_err(st, XRDC_ESOCK, "SSL_new");
        SSL_CTX_free(ctx);
        return -1;
    }

    if (verify_peer && verify_host && c->host[0] != '\0') {
        if (!brix_crypto_tls_peer_name(ssl, c->host)) {
            brix_tls_err(st, XRDC_EAUTH, "TLS host-verify setup");
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return -1;
        }
    }

    /* Non-blocking for poll-driven handshake/IO; SSL handles record framing. */
    fl = fcntl(c->io.fd, F_GETFL, 0);
    if (fl >= 0) {
        (void) fcntl(c->io.fd, F_SETFL, fl | O_NONBLOCK);
    }
    SSL_set_fd(ssl, c->io.fd);
    SSL_set_connect_state(ssl);
    if (c->opts.tls_resume_session != NULL
        && SSL_set_session(ssl,
            (SSL_SESSION *) c->opts.tls_resume_session) != 1)
    {
        brix_tls_err(st, XRDC_ESOCK, "SSL_set_session");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    if (tls_do_connect(ssl, &c->io, verify_peer, st) != 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    c->io.ssl = ssl;     /* struct ssl_st* == SSL* */
    c->ssl_ctx = ctx;
    c->tls_session_reused = SSL_session_reused(ssl) ? 1 : 0;
    return 0;
}

int
brix_tls_probe_renegotiate(brix_conn *c, brix_status *st)
{
    SSL *ssl;
    int attempts;

    if (c == NULL || c->io.ssl == NULL) return -1;
    ssl = (SSL *) c->io.ssl;
    if (SSL_version(ssl) != TLS1_2_VERSION) return -1;
    ERR_clear_error();
    if (SSL_renegotiate(ssl) != 1) {
        brix_tls_err(st, XRDC_ESOCK, "TLS renegotiation unavailable locally");
        return -1;
    }
    for (attempts = 0; attempts < 32; attempts++) {
        int rc = SSL_do_handshake(ssl);
        int error;
        short events;

        if (rc == 1) return 1;
        error = SSL_get_error(ssl, rc);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            brix_tls_err(st, XRDC_ESOCK, "TLS renegotiation refused");
            return 0;
        }
        events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        if (brix_tls_wait_io(c->io.fd, events, c->io.timeout_ms) <= 0) {
            brix_status_set(st, XRDC_ESOCK, ETIMEDOUT,
                "TLS renegotiation response unavailable");
            return -1;
        }
    }
    brix_status_set(st, XRDC_ESOCK, 0, "TLS renegotiation did not terminate");
    return -1;
}

void *
brix_tls_session_get(const brix_conn *c)
{
    if (c == NULL || c->io.ssl == NULL) return NULL;
    return SSL_get1_session((SSL *) c->io.ssl);
}

void
brix_tls_session_free(void *session)
{
    SSL_SESSION_free((SSL_SESSION *) session);
}


/*
 * Standalone TLS client handshake on an already-connected socket (io->fd), for the
 * general HTTP(S) client — independent of the root:// in-protocol upgrade. Mirrors
 * brix_tls_upgrade but takes a bare brix_io + an explicit SNI/verify host. On
 * success io->ssl holds the live SSL and *out_ctx the SSL_CTX (caller frees both via
 * brix_tls_client_free). 0 / -1.
 */
/* ---- Configure standalone client TLS credentials and trust ----
 * WHAT: Return 0 with verification configured, or -1 with a credential error.
 * WHY: HTTP copies must honor the same explicit/grid CA selection as root://;
 *      a failed credential must never become anonymous or unverified access.
 * HOW: 1. Load the complete client identity. 2. Resolve trust through the shared
 *      selector. 3. Configure peer and RFC-3820 proxy verification.
 */
static int
tls_prepare_ctx(SSL_CTX *ctx, int verify_peer, const char *ca_dir,
                const char *client_cert, brix_status *st)
{
    if (client_cert != NULL && client_cert[0] != '\0') {
        if (SSL_CTX_use_certificate_chain_file(ctx, client_cert) != 1) {
            brix_tls_err(st, XRDC_EAUTH, "load client cert");
            return -1;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, client_cert, SSL_FILETYPE_PEM) != 1) {
            brix_tls_err(st, XRDC_EAUTH, "load client key");
            return -1;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            brix_tls_err(st, XRDC_EAUTH, "client cert/key mismatch");
            return -1;
        }
    }
    if (!verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        return 0;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    ca_dir = brix_resolve_ca_dir(ca_dir);
    if (ca_dir != NULL && ca_dir[0] != '\0') {
        if (SSL_CTX_load_verify_locations(ctx, NULL, ca_dir) != 1) {
            brix_tls_err(st, XRDC_EAUTH, "load CA dir");
            return -1;
        }
    } else {
        SSL_CTX_set_default_verify_paths(ctx);
    }
    X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx),
                                X509_V_FLAG_ALLOW_PROXY_CERTS);
    return 0;
}

int
brix_tls_client(brix_io *io, const char *host, int verify_peer, int verify_host,
                const char *ca_dir, const char *client_cert, void **out_ctx,
                brix_status *st)
{
    SSL_CTX *ctx;
    SSL     *ssl;
    int      fl;

    *out_ctx = NULL;
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        brix_tls_err(st, XRDC_ESOCK, "SSL_CTX_new");
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (tls_prepare_ctx(ctx, verify_peer, ca_dir, client_cert, st) != 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        brix_tls_err(st, XRDC_ESOCK, "SSL_new");
        SSL_CTX_free(ctx);
        return -1;
    }
    if (host != NULL && host[0] != '\0') {
        SSL_set_tlsext_host_name(ssl, host);     /* SNI */
        if (verify_peer && verify_host) {
            if (!brix_crypto_tls_peer_name(ssl, host)) {
                brix_tls_err(st, XRDC_EAUTH, "TLS host-verify setup");
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                return -1;
            }
        }
    }
    fl = fcntl(io->fd, F_GETFL, 0);
    if (fl >= 0) {
        (void) fcntl(io->fd, F_SETFL, fl | O_NONBLOCK);
    }
    SSL_set_fd(ssl, io->fd);
    SSL_set_connect_state(ssl);

    if (tls_do_connect(ssl, io, verify_peer, st) != 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }
    io->ssl = ssl;
    *out_ctx = ctx;
    return 0;
}

/* Tear down a session created by brix_tls_client. */
void
brix_tls_client_free(brix_io *io, void *ctx)
{
    if (io != NULL && io->ssl != NULL) {
        SSL_shutdown((SSL *) io->ssl);
        SSL_free((SSL *) io->ssl);
        io->ssl = NULL;
    }
    if (ctx != NULL) {
        SSL_CTX_free((SSL_CTX *) ctx);
    }
}

/* Read the negotiated TLS version + cipher of a standalone client session (or NULL). */
void
brix_tls_client_info(const brix_io *io, const char **ver, const char **cipher)
{
    if (io != NULL && io->ssl != NULL) {
        if (ver != NULL)    { *ver = SSL_get_version((const SSL *) io->ssl); }
        if (cipher != NULL) { *cipher = SSL_get_cipher((const SSL *) io->ssl); }
    } else {
        if (ver != NULL)    { *ver = NULL; }
        if (cipher != NULL) { *cipher = NULL; }
    }
}

void
brix_tls_free(brix_conn *c)
{
    if (c->io.ssl != NULL) {
        SSL_shutdown((SSL *) c->io.ssl);
        SSL_free((SSL *) c->io.ssl);
        c->io.ssl = NULL;
    }
    if (c->ssl_ctx != NULL) {
        SSL_CTX_free((SSL_CTX *) c->ssl_ctx);
        c->ssl_ctx = NULL;
    }
}

int
brix_tls_info(const brix_conn *c, const char **ver, const char **cipher)
{
    if (c->io.ssl == NULL) {
        return 0;   /* cleartext */
    }
    if (ver != NULL) {
        *ver = SSL_get_version((const SSL *) c->io.ssl);
    }
    if (cipher != NULL) {
        *cipher = SSL_get_cipher_name((const SSL *) c->io.ssl);
    }
    return 1;
}
