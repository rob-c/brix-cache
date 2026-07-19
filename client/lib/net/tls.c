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
 *       io->ssl != NULL, so no other file changes for TLS.
 */
#include "brix.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void
tls_err(brix_status *st, int kxr, const char *what)
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
static int
wait_io(int fd, short events, int timeout_ms)
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

/* Clamp the idle timeout to a whole-operation deadline; see read_wait_ms in
 * sock.c for the rationale (slow-drip guard). -1 = deadline passed. */
static int
tls_read_wait_ms(int timeout_ms, uint64_t deadline_ns)
{
    if (deadline_ns == 0) {
        return timeout_ms;
    }
    {
        uint64_t now = brix_mono_ns();
        int64_t  rem_ms;

        if (now >= deadline_ns) {
            return -1;
        }
        rem_ms = (int64_t) ((deadline_ns - now) / 1000000ULL);
        if (rem_ms <= 0) {
            return -1;
        }
        if (timeout_ms > 0 && (int64_t) timeout_ms < rem_ms) {
            return timeout_ms;
        }
        return (int) rem_ms;
    }
}

int
brix_tls_read(brix_io *io, void *buf, size_t n, brix_status *st)
{
    SSL     *ssl = (SSL *) io->ssl;
    uint8_t *p   = (uint8_t *) buf;
    size_t   got = 0;
    /* Shared absolute cutoff for the whole logical operation (armed once by
     * brix_io_stall_arm), so a multi-record TLS read shares one budget rather
     * than re-arming per record. 0 = disabled. */
    uint64_t deadline_ns = io->stall_deadline_ns;

    while (got < n) {
        size_t nread = 0;
        int    ok, err;

        if (brix_copy_quit_requested()) {   /* Phase 40 (a): prompt cancel */
            brix_status_set(st, XRDC_ESOCK, EINTR, "transfer cancelled (signal)");
            return -1;
        }
        ERR_clear_error();   /* so SSL_get_error reflects THIS op, not a stale queue */
        ok = SSL_read_ex(ssl, p + got, n - got, &nread);

        if (ok == 1) {
            got += nread;
            continue;
        }
        err = SSL_get_error(ssl, 0);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            short ev = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int   wait_ms = tls_read_wait_ms(io->timeout_ms, deadline_ns);
            int   pr;

            if (wait_ms < 0) {
                brix_status_set(st, XRDC_ESOCK, ETIMEDOUT,
                                "TLS read exceeded slow-drip deadline "
                                "(%d ms, got %zu/%zu bytes)",
                                io->stall_deadline_ms, got, n);
                return -1;
            }
            pr = wait_io(io->fd, ev, wait_ms);
            if (pr == 0) {
                if (deadline_ns != 0 && brix_mono_ns() >= deadline_ns) {
                    brix_status_set(st, XRDC_ESOCK, ETIMEDOUT,
                                    "TLS read exceeded slow-drip deadline "
                                    "(%d ms, got %zu/%zu bytes)",
                                    io->stall_deadline_ms, got, n);
                    return -1;
                }
                brix_status_set(st, XRDC_ESOCK, ETIMEDOUT, "TLS read timed out");
                return -1;
            }
            if (pr < 0) {
                brix_status_set(st, XRDC_ESOCK, errno, "poll(tls read): %s",
                                strerror(errno));
                return -1;
            }
            continue;
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            brix_status_set(st, XRDC_ESOCK, 0,
                            "TLS connection closed by peer (read %zu/%zu)", got, n);
            return -1;
        }
        if (err == SSL_ERROR_SYSCALL) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            brix_status_set(st, XRDC_ESOCK, errno, "TLS read: %s",
                            errno ? strerror(errno) : "unexpected EOF");
            return -1;
        }
        tls_err(st, XRDC_ESOCK, "TLS read");
        return -1;
    }
    return 0;
}

int
brix_tls_write(brix_io *io, const void *buf, size_t n, brix_status *st)
{
    SSL           *ssl  = (SSL *) io->ssl;
    const uint8_t *p    = (const uint8_t *) buf;
    size_t         sent = 0;

    while (sent < n) {
        size_t nw = 0;
        int    ok, err;

        if (brix_copy_quit_requested()) {   /* Phase 40 (a): prompt cancel */
            brix_status_set(st, XRDC_ESOCK, EINTR, "transfer cancelled (signal)");
            return -1;
        }
        ERR_clear_error();
        ok = SSL_write_ex(ssl, p + sent, n - sent, &nw);

        if (ok == 1) {
            sent += nw;
            continue;
        }
        err = SSL_get_error(ssl, 0);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            short ev = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int   pr = wait_io(io->fd, ev, io->timeout_ms);
            if (pr == 0) {
                brix_status_set(st, XRDC_ESOCK, ETIMEDOUT, "TLS write timed out");
                return -1;
            }
            if (pr < 0) {
                brix_status_set(st, XRDC_ESOCK, errno, "poll(tls write): %s",
                                strerror(errno));
                return -1;
            }
            continue;
        }
        if (err == SSL_ERROR_SYSCALL) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            brix_status_set(st, XRDC_ESOCK, errno, "TLS write: %s",
                            errno ? strerror(errno) : "unexpected EOF");
            return -1;
        }
        tls_err(st, XRDC_ESOCK, "TLS write");
        return -1;
    }
    return 0;
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
            if (wait_io(io->fd, ev, io->timeout_ms) <= 0) {
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
                tls_err(st, XRDC_ESOCK, "SSL_connect");
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

int
brix_tls_upgrade(brix_conn *c, int verify_peer, int verify_host,
                 const char *ca_dir, brix_status *st)
{
    SSL_CTX *ctx;
    SSL     *ssl;
    int      fl;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        tls_err(st, XRDC_ESOCK, "SSL_CTX_new");
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (ca_dir != NULL && ca_dir[0] != '\0') {
            if (SSL_CTX_load_verify_locations(ctx, NULL, ca_dir) != 1) {
                tls_err(st, XRDC_EAUTH, "load CA dir");
                SSL_CTX_free(ctx);
                return -1;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
        /* Permit proxy certs in the chain (GSI deployments). */
        X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx),
                                    X509_V_FLAG_ALLOW_PROXY_CERTS);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        tls_err(st, XRDC_ESOCK, "SSL_new");
        SSL_CTX_free(ctx);
        return -1;
    }

    if (verify_peer && verify_host && c->host[0] != '\0') {
        SSL_set1_host(ssl, c->host);
    }

    /* Non-blocking for poll-driven handshake/IO; SSL handles record framing. */
    fl = fcntl(c->io.fd, F_GETFL, 0);
    if (fl >= 0) {
        (void) fcntl(c->io.fd, F_SETFL, fl | O_NONBLOCK);
    }
    SSL_set_fd(ssl, c->io.fd);
    SSL_set_connect_state(ssl);

    if (tls_do_connect(ssl, &c->io, verify_peer, st) != 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    c->io.ssl = ssl;     /* struct ssl_st* == SSL* */
    c->ssl_ctx = ctx;
    return 0;
}

/*
 * Read UP TO n bytes (one record) over TLS — unlike brix_tls_read (which fills
 * exactly n for root:// framing), this is a stream read for the HTTP client: sets
 * *got to the bytes read (0 = clean EOF / peer close) and returns 0, or -1 on error.
 */
int
brix_tls_read_some(brix_io *io, void *buf, size_t n, size_t *got, brix_status *st)
{
    SSL   *ssl = (SSL *) io->ssl;
    size_t nread = 0;

    *got = 0;
    for (;;) {
        int ok, err;
        ERR_clear_error();
        ok = SSL_read_ex(ssl, buf, n, &nread);
        if (ok == 1) {
            *got = nread;
            return 0;
        }
        err = SSL_get_error(ssl, 0);
        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;                    /* clean close → *got stays 0 (EOF) */
        }
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            short ev = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int   pr = wait_io(io->fd, ev, io->timeout_ms);
            if (pr <= 0) {
                brix_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno,
                                "TLS read %s", pr == 0 ? "timed out" : "poll failed");
                return -1;
            }
            continue;
        }
        if (err == SSL_ERROR_SYSCALL && errno == 0) {
            return 0;                    /* unclean EOF — treat as end of body */
        }
        if (err == SSL_ERROR_SYSCALL && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        tls_err(st, XRDC_ESOCK, "TLS read");
        return -1;
    }
}

/*
 * Standalone TLS client handshake on an already-connected socket (io->fd), for the
 * general HTTP(S) client — independent of the root:// in-protocol upgrade. Mirrors
 * brix_tls_upgrade but takes a bare brix_io + an explicit SNI/verify host. On
 * success io->ssl holds the live SSL and *out_ctx the SSL_CTX (caller frees both via
 * brix_tls_client_free). 0 / -1.
 */
int
brix_tls_client(brix_io *io, const char *host, int verify_peer, int verify_host,
                const char *ca_dir, void **out_ctx, brix_status *st)
{
    SSL_CTX *ctx;
    SSL     *ssl;
    int      fl;

    *out_ctx = NULL;
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        tls_err(st, XRDC_ESOCK, "SSL_CTX_new");
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (ca_dir != NULL && ca_dir[0] != '\0') {
            if (SSL_CTX_load_verify_locations(ctx, NULL, ca_dir) != 1) {
                tls_err(st, XRDC_EAUTH, "load CA dir");
                SSL_CTX_free(ctx);
                return -1;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
        X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx),
                                    X509_V_FLAG_ALLOW_PROXY_CERTS);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        tls_err(st, XRDC_ESOCK, "SSL_new");
        SSL_CTX_free(ctx);
        return -1;
    }
    if (host != NULL && host[0] != '\0') {
        SSL_set_tlsext_host_name(ssl, host);     /* SNI */
        if (verify_peer && verify_host) {
            SSL_set1_host(ssl, host);
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

/* Join the cert's DNS subjectAltNames into out[] as a comma-separated list. */
static void
peer_collect_sans(X509 *cert, char *out, size_t outsz)
{
    GENERAL_NAMES *gens;
    int            i, n;
    size_t         off = 0;

    out[0] = '\0';
    gens = (GENERAL_NAMES *) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (gens == NULL) {
        return;
    }
    n = sk_GENERAL_NAME_num(gens);
    for (i = 0; i < n; i++) {
        GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
        const char   *dns;
        int           len;
        if (g->type != GEN_DNS) {
            continue;
        }
        dns = (const char *) ASN1_STRING_get0_data(g->d.dNSName);
        len = ASN1_STRING_length(g->d.dNSName);
        if (len <= 0 || off + (size_t) len + 2 >= outsz) {
            continue;
        }
        if (off > 0) { out[off++] = ','; }
        memcpy(out + off, dns, (size_t) len);
        off += (size_t) len;
        out[off] = '\0';
    }
    GENERAL_NAMES_free(gens);
}

int
brix_tls_peer_cert_info(const brix_conn *c, brix_cert_info *out)
{
    SSL             *ssl = (SSL *) c->io.ssl;
    X509            *cert;
    const ASN1_TIME *nb, *na;
    struct tm        tmv;
    time_t           now = time(NULL);
    int              dd = 0, ds = 0;

    memset(out, 0, sizeof(*out));
    if (ssl == NULL) {
        return -1;   /* cleartext: no peer cert */
    }
    cert = SSL_get_peer_certificate(ssl);   /* bumps refcount; free below */
    if (cert == NULL) {
        return -1;
    }
    out->have = 1;
    X509_NAME_oneline(X509_get_subject_name(cert), out->subject, sizeof(out->subject));
    X509_NAME_oneline(X509_get_issuer_name(cert),  out->issuer,  sizeof(out->issuer));
    out->self_signed = (X509_check_issued(cert, cert) == X509_V_OK);
    out->host_match  = (c->host[0] != '\0'
                        && X509_check_host(cert, c->host, 0, 0, NULL) == 1);

    nb = X509_get0_notBefore(cert);
    na = X509_get0_notAfter(cert);
    if (ASN1_TIME_to_tm(nb, &tmv)) { out->not_before = (long) timegm(&tmv); }
    if (ASN1_TIME_to_tm(na, &tmv)) { out->not_after  = (long) timegm(&tmv); }
    out->expired       = (out->not_after  != 0 && out->not_after  < (long) now);
    out->not_yet_valid = (out->not_before != 0 && out->not_before > (long) now);
    if (ASN1_TIME_diff(&dd, &ds, NULL, na)) {
        out->days_left = dd;   /* whole days; negative once expired */
    }
    peer_collect_sans(cert, out->sans, sizeof(out->sans));

    X509_free(cert);
    return 0;
}
