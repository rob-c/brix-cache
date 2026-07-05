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
 * HOW: SSL_CTX_new(TLS_client_method) → min TLS 1.2 → if brix_trusted_ca is set,
 *   load it as a CA directory and SSL_VERIFY_PEER (chain verification; on load
 *   failure fall back to no verification so an encrypted-but-unverified transport
 *   still works) → SSL_new + SSL_set_fd(fd) + SNI(src_host) → SSL_connect. On any
 *   failure t->err_msg / t->xrd_error are set and all OpenSSL objects freed.
 *   Gated by the caller on conf->tpc_outbound_tls (bootstrap.c). (phase-57 §F5) */

#include "tpc/engine/tpc_internal.h"
#include "core/compat/cstr.h"

#include <string.h>
#include <limits.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* WHAT: blocking client TLS handshake over the pull fd; stores SSL on t->tls.
 * Returns 0 on success, -1 with t->err_msg / t->xrd_error set on failure. */
int
tpc_start_tls(brix_tpc_pull_t *t, int fd)
{
    SSL_CTX *ctx;
    SSL     *ssl;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC TLS: SSL_CTX_new failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* Verify the source's certificate chain against brix_trusted_ca when it is
     * configured (treated as a CA directory). If the CA store cannot be loaded,
     * downgrade to an encrypted-but-unverified transport rather than failing the
     * pull outright. When chain verification IS active we ALSO bind the expected
     * hostname below (verify_host) — chain-only would accept any CA-valid cert
     * for any host, a MITM gap. */
    int verify_host = 0;
    if (t->conf->trusted_ca.len > 0 && t->conf->trusted_ca.len < PATH_MAX) {
        char cadir[PATH_MAX];

        if (brix_str_cbuf(cadir, sizeof(cadir), &t->conf->trusted_ca) != NULL
            && SSL_CTX_load_verify_locations(ctx, NULL, cadir) == 1) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            verify_host = 1;
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC TLS: SSL_new failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    SSL_set_fd(ssl, fd);
    if (t->src_host[0] != '\0') {
        (void) SSL_set_tlsext_host_name(ssl, t->src_host);
        /* Only meaningful when the chain is actually being verified. */
        if (verify_host) {
            SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (SSL_set1_host(ssl, t->src_host) != 1) {
                snprintf(t->err_msg, sizeof(t->err_msg),
                         "TPC TLS: host-verify setup failed");
                t->xrd_error = kXR_ServerError;
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                return -1;
            }
        }
    }

    if (SSL_connect(ssl) != 1) {
        char ebuf[160];

        ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC TLS handshake to source failed: %s", ebuf);
        t->xrd_error = kXR_NotAuthorized;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    t->tls     = ssl;
    t->tls_ctx = ctx;
    return 0;
}

/* WHAT: release the pull's TLS objects (NULL-safe); called from thread.c teardown. */
void
tpc_tls_teardown(brix_tpc_pull_t *t)
{
    if (t->tls != NULL) {
        (void) SSL_shutdown((SSL *) t->tls);
        SSL_free((SSL *) t->tls);
        t->tls = NULL;
    }
    if (t->tls_ctx != NULL) {
        SSL_CTX_free((SSL_CTX *) t->tls_ctx);
        t->tls_ctx = NULL;
    }
}
