/* File: tls.c — TPC pull in-protocol TLS upgrade (kXR_gotoTLS)
 * WHAT: tpc_start_tls() performs a blocking client TLS handshake over the already
 *   connected TPC pull socket after the source answered the kXR_protocol request
 *   with kXR_gotoTLS; it stores the negotiated SSL on t->tls (and its per-pull
 *   SSL_CTX on t->tls_ctx) so the low-level I/O helpers (src/tpc/outbound/io.c) route every
 *   subsequent frame — login, GSI/ztn auth, open/read/close — through SSL_read /
 *   SSL_write. tpc_tls_teardown() releases both.
 *
 * WHY: A source that mandates in-protocol TLS (xrd.tls / a TLS-only sec.protbind)
 *   cannot be pulled from over plaintext (phase-57 W1 gap 2). The native client
 *   already does this; the destination's pull path did not. Because the TPC pull
 *   runs on a thread-pool worker (a blocking context, not the nginx event loop),
 *   we use a synchronous SSL_connect over the blocking fd rather than nginx's
 *   async ngx_ssl_handshake.
 *
 * HOW: SSL_CTX_new(TLS_client_method) → min TLS 1.2 → require either the
 *   configured CA file/directory or OpenSSL's default trust paths → require
 *   chain verification → SSL_new + SSL_set_fd(fd) + SNI/peer-name pin on
 *   src_host, folded out of its IPv4-mapped spelling first → SSL_connect →
 *   require X509_V_OK → publish the SSL and verified state together. On any
 *   failure t->err_msg / t->xrd_error are set and all OpenSSL objects freed.
 *   Gated by the caller on conf->tpc_outbound_tls (bootstrap.c). (phase-57 §F5) */

#include "tpc/engine/tpc_internal.h"
#include "auth/crypto/tls_compat.h"
#include "core/compat/cstr.h"
#include "core/compat/host_format.h"

#include <string.h>
#include <limits.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* ---- Publish a verified TLS session on its owning socket ------------------
 *
 * WHAT: Stores a successfully authenticated SSL/SSL_CTX pair and its verified
 *       bit on the matching sub-stream or primary task.
 * WHY: Credential disclosure checks must observe transport and authentication
 *      state atomically; publishing the pointer without the bit would create an
 *      encrypted-but-unverified intermediate state.
 * HOW: Resolve the bounded sub-stream slots by fd, otherwise require the
 *      primary socket's exact fd, then set the corresponding verified bit last. */
static int
tpc_tls_store(brix_tpc_pull_t *t, int fd, SSL *ssl, SSL_CTX *ctx)
{
    int i;

    for (i = 0; i < t->nsub; i++) {
        if (t->sub[i].fd == fd) {
            t->sub[i].tls     = ssl;
            t->sub[i].tls_ctx = ctx;
            t->sub[i].tls_verified = 1;
            return 0;
        }
    }
    if (fd == t->primary_fd) {
        t->tls     = ssl;
        t->tls_ctx = ctx;
        t->tls_verified = 1;
        return 0;
    }
    return -1;
}

/* ---- Load a fail-closed TLS trust store ----------------------------------
 *
 * WHAT: Enables peer verification and loads the configured CA file/directory,
 *       or the system defaults when no path is configured. Returns 0 on a
 *       usable store and -1 with an authorization error otherwise.
 * WHY: A missing or unloadable trust root must never silently convert a
 *      credential-bearing TPC session into unauthenticated encryption.
 * HOW: Require SSL_VERIFY_PEER; for an explicit path try CAfile then CApath
 *      (the directive supports both), clearing failed-probe errors; otherwise
 *      require OpenSSL's default paths. */
static int
tpc_tls_load_verify(brix_tpc_pull_t *t, SSL_CTX *ctx)
{
    char trust[PATH_MAX];

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (t->conf->common.trusted_ca.len == 0) {
        if (SSL_CTX_set_default_verify_paths(ctx) == 1) {
            ERR_clear_error();
            return 0;
        }
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC TLS: default trust store unavailable");
        t->xrd_error = kXR_NotAuthorized;
        return -1;
    }

    if (brix_str_cbuf(trust, sizeof(trust),
                      &t->conf->common.trusted_ca) == NULL)
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC TLS: configured trust path is invalid");
        t->xrd_error = kXR_NotAuthorized;
        return -1;
    }

    if (SSL_CTX_load_verify_locations(ctx, trust, NULL) == 1) {
        ERR_clear_error();
        return 0;
    }
    ERR_clear_error();
    if (SSL_CTX_load_verify_locations(ctx, NULL, trust) == 1) {
        ERR_clear_error();
        return 0;
    }

    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC TLS: configured trust store cannot be loaded");
    t->xrd_error = kXR_NotAuthorized;
    return -1;
}

/* ---- Bind source identity verification to a TLS session ------------------
 *
 * WHAT: Configures strict hostname or IP verification for t->src_host and SNI;
 *       returns 0 on success and -1 with an authorization error on failure.
 * WHY: Chain validation alone accepts any CA-valid certificate, while a missing
 *      source name would make an authenticated transport claim impossible.
 * HOW: Require a non-empty source name, fold IPv4-mapped spelling to its IPv4
 *      identity, disable partial wildcards, bind OpenSSL's DNS/IP verifier, and
 *      send the same normalized name as SNI. */
static int
tpc_tls_bind_peer_name(brix_tpc_pull_t *t, SSL *ssl)
{
    char vhost[sizeof(t->src_host)];

    if (t->src_host[0] == '\0') {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC TLS: source name is unavailable for verification");
        t->xrd_error = kXR_NotAuthorized;
        return -1;
    }
    if (!brix_host_unmap_v4(t->src_host, vhost, sizeof(vhost))) {
        ngx_cpystrn((u_char *) vhost, (u_char *) t->src_host,
                    sizeof(vhost));
    }

    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!brix_crypto_tls_peer_name(ssl, vhost)) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC TLS: host-verify setup failed");
        t->xrd_error = kXR_NotAuthorized;
        return -1;
    }
    if (SSL_set_tlsext_host_name(ssl, vhost) != 1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC TLS: SNI setup failed");
        t->xrd_error = kXR_NotAuthorized;
        return -1;
    }
    return 0;
}

/* ---- Establish authenticated TLS on a TPC source socket ------------------
 *
 * WHAT: Performs a blocking TLS 1.2+ client handshake on fd and publishes the
 *       session only after trust-chain and source-name verification succeed.
 *       Returns 0 on success or -1 with t->err_msg/t->xrd_error set.
 * WHY: Native TPC can carry reusable bearer credentials, so encryption without
 *      peer authentication is not a safe transport state.
 * HOW: Allocate the context, load a mandatory trust store, allocate/bind SSL,
 *      bind source identity, connect, require X509_V_OK, then store the verified
 *      session. Every failure frees all locally owned OpenSSL objects. */
int
tpc_start_tls(brix_tpc_pull_t *t, int fd)
{
    SSL_CTX *ctx;
    SSL     *ssl;
    long     verify_result;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC TLS: SSL_CTX_new failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (tpc_tls_load_verify(t, ctx) != 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC TLS: SSL_new failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (SSL_set_fd(ssl, fd) != 1 || tpc_tls_bind_peer_name(t, ssl) != 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    if (SSL_connect(ssl) != 1) {
        char ebuf[160];
        long vres;

        ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));

        /* "certificate verify failed" on its own is unactionable — the reason
         * (unknown issuer vs expired vs hostname mismatch) is what tells the
         * operator whether brix_trusted_ca or the source's certificate is
         * wrong, and it lives on the SSL, not in the error queue. */
        vres = SSL_get_verify_result(ssl);
        if (vres != X509_V_OK) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC TLS handshake to source failed: %s (%s)",
                     ebuf, X509_verify_cert_error_string(vres));
        } else {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC TLS handshake to source failed: %s", ebuf);
        }
        t->xrd_error = kXR_NotAuthorized;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC TLS source verification failed: %s",
                 X509_verify_cert_error_string(verify_result));
        t->xrd_error = kXR_NotAuthorized;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    if (tpc_tls_store(t, fd, ssl, ctx) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC TLS: socket ownership changed during handshake");
        t->xrd_error = kXR_NotAuthorized;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }
    return 0;
}

/* WHAT: release one (tls, tls_ctx) pair in place; NULL-safe. */
static void
tpc_tls_release(void **tls, void **tls_ctx)
{
    if (*tls != NULL) {
        (void) SSL_shutdown((SSL *) *tls);
        SSL_free((SSL *) *tls);
        *tls = NULL;
    }
    if (*tls_ctx != NULL) {
        SSL_CTX_free((SSL_CTX *) *tls_ctx);
        *tls_ctx = NULL;
    }
}

/* ---- Release the primary TLS session -------------------------------------
 *
 * WHAT: Frees the primary SSL/SSL_CTX pair and clears its verified state.
 * WHY: Redirected or completed pulls must not carry authenticated-transport
 *      state onto a later raw socket.
 * HOW: Release the owned OpenSSL objects, then clear the publication bit. */
void
tpc_tls_teardown(brix_tpc_pull_t *t)
{
    tpc_tls_release(&t->tls, &t->tls_ctx);
    t->tls_verified = 0;
}

/* ---- Release the TLS session owned by an fd -------------------------------
 *
 * WHAT: Frees a matching sub-stream's TLS pair and clears its verified state,
 *       or delegates to the primary teardown when no sub-stream owns fd.
 * WHY: Each bound fd has independent transport security and must lose both the
 *      session and disclosure authorization together.
 * HOW: Walk the bounded active slots, release and clear the match, otherwise
 *      release the primary session only for its exact fd. */
void
tpc_tls_teardown_fd(brix_tpc_pull_t *t, int fd)
{
    int i;

    for (i = 0; i < t->nsub; i++) {
        if (t->sub[i].fd == fd) {
            tpc_tls_release(&t->sub[i].tls, &t->sub[i].tls_ctx);
            t->sub[i].tls_verified = 0;
            return;
        }
    }
    if (fd == t->primary_fd) {
        tpc_tls_teardown(t);
    }
}
