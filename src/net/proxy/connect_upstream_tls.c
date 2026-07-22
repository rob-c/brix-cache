/*
 * connect_upstream_tls.c — upstream TLS handshake completion callback.
 *
 * WHAT: nginx SSL callback invoked after the upstream TLS handshake completes;
 *       restores normal read/write handlers, transitions into the bootstrap
 *       state, flushes the bootstrap buffer, and arms events.
 *
 * WHY: Split out of connect_upstream.c as a self-contained concept. TLS runs
 *      asynchronously; when it finishes we must switch back from the SSL handler
 *      to brix_proxy_read_handler so the bootstrap response can be parsed.
 */

#include "proxy_internal.h"

/* TLS handshake callback */
#if (NGX_SSL)
void
brix_proxy_tls_handshake_done(ngx_connection_t *uconn)
{
    brix_proxy_ctx_t *proxy = uconn->data;
    brix_ctx_t       *ctx   = proxy->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        brix_proxy_cleanup(proxy);
        return;
    }

    if (!uconn->ssl->handshaked) {
        BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_abort(proxy, "proxy: upstream TLS handshake failed");
        return;
    }

    /* Belt-and-braces: when verification is enabled on the CTX a bad chain/host
     * already fails the handshake above; this makes the trust decision explicit
     * and survives refactors. Harmless (X509_V_OK) when verification is off. */
    if (SSL_get_verify_result(uconn->ssl->connection) != X509_V_OK) {
        BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_abort(proxy, "proxy: upstream TLS peer verification failed");
        return;
    }

    /* Restore normal event handlers and transition to bootstrap */
    uconn->read->handler  = brix_proxy_read_handler;
    uconn->write->handler = brix_proxy_write_handler;
    proxy->state    = XRD_PX_BOOTSTRAP;
    proxy->bs_phase = XRD_PX_BS_HANDSHAKE;
    proxy->rhdr_pos = 0;

    if (brix_proxy_flush(proxy) == NGX_ERROR) {
        BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_abort(proxy, "proxy: upstream write after TLS failed");
        return;
    }

    if (proxy->wbuf_pos < proxy->wbuf_len) {
        if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
            BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
            BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
            brix_proxy_abort(proxy, "proxy: write arm after TLS failed");
        }
        return;
    }

    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_abort(proxy, "proxy: read arm after TLS failed");
    }
}
/*
 * WHAT: nginx SSL callback invoked after upstream TLS handshake completes.
 *       Restores normal read/write handlers, transitions state to BOOTSTRAP,
 *       flushes the bootstrap buffer, and arms both read and write events.
 *
 * WHY: TLS handshake runs asynchronously; when it finishes we must switch back
 *      from the SSL handler to brix_proxy_read_handler so the bootstrap
 *      response can be parsed. If the client session was destroyed during
 *      handshake we clean up immediately.
 *
 * HOW: Checks ctx validity and uconn->ssl->handshaked, increments error metrics
 *      on failure, restores read/write handlers, sets state to XRD_PX_BOOTSTRAP,
 *      calls brix_proxy_flush() to send bootstrap data, then arms write event
 *      if unsent bytes remain and read event for upstream response parsing.
 */

#endif /* NGX_SSL */
