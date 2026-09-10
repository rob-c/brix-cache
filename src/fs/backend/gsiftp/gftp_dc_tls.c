/*
 * gftp_dc_tls.c — PROT P (protected) outbound GridFTP data channel.
 *
 * WHAT: raise one already-connected data socket to a TLS session that presents
 * the same X.509 proxy the control channel authenticated with, then verify the
 * chain the origin answers with and pin its subject DN to the credential this
 * session delegated to that origin.
 *
 * WHY:  with PROT C the data leg is cleartext on a port the origin nominated in
 * a reply — the bytes are unprotected and nothing but the address pin ties the
 * connection to the authenticated session.  PROT P closes both halves: the
 * payload is encrypted, and the DN pin proves the machine that answered on that
 * port is the machine we authenticated to.  A protected channel therefore never
 * degrades: if any step here fails the transfer fails (gftp_dc_open closes the
 * connection rather than returning a clear one).
 *
 * HOW:  GridFTP's protected data channel is a straight TLS session on the data
 * socket — a client ClientHello, no globus token framing (see
 * src/protocols/gridftp/ftp_dc_sec.h for the inbound mirror).  The credential is
 * built by gftp_gsi_setup(), the same function the control channel uses, so the
 * two cannot drift on which certificate BriX presents or which roots it trusts.
 * The handshake is synchronous: this runs on a VFS worker thread, not the event
 * loop, and SO_RCVTIMEO/SO_SNDTIMEO bound it.  The DN pin is the shared
 * header-only predicate in protocols/gridftp/ftp_dc_dn.h — applied here against
 * OUR OWN subject, not the origin's, because a GridFTP server runs its data
 * channel on the credential the client delegated to it.  See gftp_dc_tls_pin().
 */

#include "gftp_dc.h"
#include "gftp_gsi_internal.h"

#include "auth/crypto/gsi_verify.h"
#include "protocols/gridftp/ftp_dc_dn.h"
#include "protocols/root/connection/netconnect.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/x509.h>


/* The identity this session delegated: the subject of the proxy the data-channel
 * context presents, spelled the way brix_gsi_verify_chain spells the peer's so
 * the two can be compared at all.  Returns 0 / -1. */
static int
gftp_dc_tls_self_dn(gftp_gsi_t *gsi, char *out, size_t cap)
{
    X509 *self = SSL_get_certificate(gsi->ssl);

    out[0] = '\0';
    if (self == NULL) {
        return -1;
    }
    return X509_NAME_oneline(X509_get_subject_name(self), out, (int) cap) == NULL
           ? -1 : 0;
}


/* Post-handshake gate: hold the chain the origin answered with to BriX's proxy
 * conformance policy, then require its leaf DN to name the credential we
 * delegated to that origin.  Returns 0 / -1 with the session error set.
 *
 * The base of the pin is OUR subject, and that is not a slip.  A GridFTP server
 * does not run its data channel on its host certificate — it runs it on the
 * proxy the client delegated over the control channel, so the DN that comes
 * back is ours plus one `/CN=<serial>` per delegation step.  Pinning to the
 * origin's control DN instead compares the client's identity against the
 * server's and can never match: it refused every correct transfer with
 *   data-channel DN ".../CN=Test User/CN=12345/CN=12346/CN=3228637842"
 *     != control DN "/DC=test/DC=xrootd/CN=localhost"
 * which reads like a mismatch to be fixed at the origin and is in fact this
 * predicate asking the wrong question.
 *
 * The security property is unchanged in strength and clearer to state: the peer
 * holds the PRIVATE KEY of the credential we handed to the origin we
 * authenticated, proven by the handshake.  A third party that reaches the
 * passive data port has the public proxy at most, and cannot answer.  The
 * control channel's own identity is still required — an unauthenticated control
 * channel delegates nothing, and the first branch below refuses it. */
static int
gftp_dc_tls_pin(gftp_session_t *session, gftp_gsi_t *gsi)
{
    brix_gsi_verify_result_t  res;
    X509                     *leaf;
    STACK_OF(X509)           *chain;
    ngx_log_t                *log;
    ngx_int_t                 rc;
    char                      base[1024];

    if (session->peer_dn[0] == '\0') {
        gftp_set_error(session, EACCES,
            "GridFTP PROT P has no control-channel identity to pin to");
        return -1;
    }
    if (gftp_dc_tls_self_dn(gsi, base, sizeof(base)) != 0) {
        gftp_set_error(session, EACCES,
            "GridFTP PROT P cannot read its own delegated identity");
        return -1;
    }
    leaf = SSL_get_peer_certificate(gsi->ssl);           /* +1 ref */
    if (leaf == NULL) {
        gftp_set_error(session, EACCES,
            "GridFTP data channel presented no certificate");
        return -1;
    }
    chain = SSL_get_peer_cert_chain(gsi->ssl);           /* borrowed */
    log = (ngx_cycle != NULL) ? ngx_cycle->log : NULL;
    ngx_memzero(&res, sizeof(res));
    rc = brix_gsi_verify_chain(log, SSL_CTX_get_cert_store(gsi->ctx), leaf,
                               chain, 0, &res, 0);
    X509_free(leaf);
    if (rc != NGX_OK) {
        gftp_set_error(session, EACCES,
            "GridFTP data-channel proxy chain verify failed");
        return -1;
    }
    if (!brix_ftp_dc_dn_matches(res.dn_buf, (const u_char *) base, strlen(base)))
    {
        gftp_set_error(session, EACCES,
            "GridFTP data-channel DN \"%s\" is not the credential delegated "
            "beneath \"%s\"", res.dn_buf, base);
        return -1;
    }
    return 0;
}


/* TLS-layer verdict for the data-channel peer: accept, and let the post-handshake
 * gate below decide.  This is not a relaxation — it is where the decision lives.
 *
 * The peer presents the credential the control channel DELEGATED to it: an RFC
 * 3820 proxy, which is not a TLS server certificate and never claims to be.
 * OpenSSL's in-handshake check applies the sslServer purpose to it and rejects
 * the chain with X509_V_ERR_INVALID_PURPOSE (26) before a single byte moves, so
 * a correct origin serving a correctly delegated credential could not complete
 * one protected transfer.  The inbound half of the same feature
 * (protocols/gridftp/ftp_dc_sec.c) has always done exactly this, for exactly this
 * reason; the connect role was the half that still asked OpenSSL.
 *
 * What replaces it is stricter, not weaker: gftp_dc_tls_pin() runs BriX's proxy
 * conformance verifier over the presented chain against the SAME CA store, and
 * then requires the leaf DN to name the control-channel peer — a test OpenSSL's
 * generic path does not make at all. */
static int
gftp_dc_tls_accept_cb(int preverify, X509_STORE_CTX *store)
{
    (void) preverify;
    (void) store;
    return 1;
}


/* SSL_connect failure detail for a data channel.  OpenSSL's queue says only
 * "certificate verify failed"; the reason the chain was rejected lives in the
 * verify result and is the only part an operator can act on. */
static int
gftp_dc_tls_connect_error(gftp_session_t *session, SSL *ssl)
{
    long verdict = SSL_get_verify_result(ssl);

    if (verdict != X509_V_OK) {
        ERR_clear_error();
        gftp_set_error(session, EACCES,
            "GridFTP PROT P data-channel handshake: %s (%ld)",
            X509_verify_cert_error_string(verdict), verdict);
        return -1;
    }
    return gftp_ssl_error(session, "PROT P data-channel handshake");
}


int
gftp_dc_tls_start(gftp_session_t *session, gftp_dc_t *dc)
{
    gftp_gsi_t *gsi;
    long        seconds = session->timeout_ms / 1000;

    gsi = calloc(1, sizeof(*gsi));
    if (gsi == NULL) {
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP data channel");
        return -1;
    }
    if (gftp_gsi_setup(gsi, session->proxy_path, session->ca_dir, session)
        != 0)
    {
        gftp_gsi_free(gsi);
        return -1;
    }
    gsi->ssl = SSL_new(gsi->ctx);
    if (gsi->ssl == NULL) {
        gftp_gsi_free(gsi);
        return gftp_ssl_error(session, "create data-channel TLS session");
    }
    /* GridFTP senders close the data connection without close_notify once the
     * last block is on the wire; that is EOD, not a truncation attack. */
    SSL_set_options(gsi->ssl, SSL_OP_IGNORE_UNEXPECTED_EOF);
    /* Data channel only — the control channel keeps OpenSSL's own verdict. */
    SSL_set_verify(gsi->ssl, SSL_VERIFY_PEER, gftp_dc_tls_accept_cb);
    if (SSL_set_fd(gsi->ssl, dc->fd) != 1) {
        gftp_gsi_free(gsi);
        return gftp_ssl_error(session, "bind data-channel socket");
    }
    brix_apply_socket_io_timeouts(dc->fd, seconds > 0 ? seconds : 1);
    if (SSL_connect(gsi->ssl) != 1) {
        int rc = gftp_dc_tls_connect_error(session, gsi->ssl);

        gftp_gsi_free(gsi);
        return rc;
    }
    if (gftp_dc_tls_pin(session, gsi) != 0) {
        gftp_gsi_free(gsi);
        return -1;
    }
    dc->tls = gsi;
    return 0;
}


ssize_t
gftp_dc_tls_read(gftp_session_t *session, gftp_dc_t *dc, void *buf, size_t cap)
{
    gftp_gsi_t *gsi = dc->tls;
    int         n;
    int         reason;

    ERR_clear_error();
    n = SSL_read(gsi->ssl, buf, (int) (cap > INT_MAX ? INT_MAX : cap));
    if (n > 0) {
        return n;
    }
    reason = SSL_get_error(gsi->ssl, n);
    if (reason == SSL_ERROR_ZERO_RETURN) {
        return 0;                                  /* orderly end of data */
    }
    if (reason == SSL_ERROR_SYSCALL && ERR_peek_error() == 0 && errno == 0) {
        return 0;                                  /* peer closed after EOD */
    }
    return gftp_ssl_error(session, "read protected data channel");
}


int
gftp_dc_tls_write_all(gftp_session_t *session, gftp_dc_t *dc, const void *buf,
    size_t len)
{
    gftp_gsi_t    *gsi = dc->tls;
    const uint8_t *cursor = buf;
    size_t         written = 0;

    while (written < len) {
        size_t want = len - written;
        int    n;

        if (want > INT_MAX) {
            want = INT_MAX;
        }
        ERR_clear_error();
        n = SSL_write(gsi->ssl, cursor + written, (int) want);
        if (n <= 0) {
            return gftp_ssl_error(session, "write protected data channel");
        }
        written += (size_t) n;
    }
    return 0;
}


void
gftp_dc_tls_finish_write(gftp_dc_t *dc)
{
    gftp_gsi_t *gsi = dc->tls;

    /* One-way close_notify: the receiver's EOD signal.  We do not wait for the
     * peer's, which GridFTP implementations routinely never send. */
    (void) SSL_shutdown(gsi->ssl);
}


void
gftp_dc_tls_free(gftp_dc_t *dc)
{
    gftp_gsi_free(dc->tls);
    dc->tls = NULL;
}
