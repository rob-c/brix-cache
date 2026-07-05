#include "proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include "core/compat/log_diag.h"
#include <sys/socket.h>

/*
 * WHAT: Handle upstream write events — TCP connect validation, TLS handshake initiation (if configured),
 *      buffered data flush to upstream, and read event arming after write completes.
 * WHY: nginx-xrootd proxy buffers client requests before writing them to the upstream XRootD server.
 *      The first write event is special because it must validate TCP connectivity, optionally initiate TLS,
 *      then transition into bootstrap phase for protocol negotiation. Subsequent write events flush the buffer.
 * HOW: Extract uconn and proxy ctx from wev->data; check client destruction/timeout; delegate TLS to SSL layer;
 *      on CONNECTING state: getsockopt SO_ERROR for connect validation + optional ngx_ssl_create_connection for TLS;
 *      transition to XRD_PX_BOOTSTRAP then flush wbuf via brix_proxy_flush(); arm upstream read event after write done.
 */

/* write event handler */
void
brix_proxy_write_handler(ngx_event_t *wev)
{
    ngx_connection_t   *uconn = wev->data;
    brix_proxy_ctx_t *proxy = uconn->data;
    brix_ctx_t       *ctx;

    if (proxy == NULL) {
        return;
    }
    ctx = proxy->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        brix_proxy_cleanup(proxy);
        return;
    }

    if (wev->timedout) {
        brix_proxy_abort(proxy, "proxy: upstream write timeout");
        return;
    }

    /* TLS handshake is driven by the SSL layer, not the write handler */
    if (proxy->state == XRD_PX_TLS_HANDSHAKE) {
        return;
    }

    /* On first write event after connect(), check socket error */
    if (proxy->state == XRD_PX_CONNECTING) {
        int       err = 0;
        socklen_t len = sizeof(err);

        if (getsockopt(uconn->fd, SOL_SOCKET, SO_ERROR,
                       (char *) &err, &len) == -1 || err)
        {
            BRIX_DIAG_ERR(proxy->client_conn->log,
                err ? err : ngx_socket_errno,
                "xrootd proxy: cannot connect to the backend",
                "the proxied backend is down, unreachable, or refusing "
                "connections (wrong host/port, or a firewall)",
                "confirm the backend in brix_proxy_pass is up and reachable "
                "from this host; the OS reason is appended below");
            BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
            BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
            brix_proxy_abort(proxy, "proxy: TCP connect failed");
            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                       "xrootd proxy: upstream TCP connected");

        /* Remove the connect-timeout timer — it must not fire during normal use. */
        if (uconn->write->timer_set) {
            ngx_del_timer(uconn->write);
        }

#if (NGX_SSL)
        if (proxy->conf != NULL
            && proxy->conf->proxy.upstream_tls
            && proxy->conf->proxy.tls_ctx != NULL)
        {
            if (ngx_ssl_create_connection(proxy->conf->proxy.tls_ctx, uconn,
                                          NGX_SSL_BUFFER | NGX_SSL_CLIENT)
                != NGX_OK)
            {
                BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
                BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
                brix_proxy_abort(proxy, "proxy: TLS setup failed");
                return;
            }
            /* SNI: prefer explicit name directive, fall back to configured host */
            {
                const char *sni =
                    (proxy->conf->proxy.upstream_tls_name.len > 0)
                    ? (const char *) proxy->conf->proxy.upstream_tls_name.data
                    : (const char *) proxy->conf->proxy.host.data;
                SSL_set_tlsext_host_name(uconn->ssl->connection, sni);
            }
            uconn->ssl->handler = brix_proxy_tls_handshake_done;
            proxy->state = XRD_PX_TLS_HANDSHAKE;
            if (ngx_ssl_handshake(uconn) != NGX_AGAIN) {
                brix_proxy_tls_handshake_done(uconn);
            }
            return;
        }
#endif

        proxy->state    = XRD_PX_BOOTSTRAP;
        proxy->bs_phase = XRD_PX_BS_HANDSHAKE;
        proxy->rhdr_pos = 0;
    }

    if (proxy->wbuf_pos < proxy->wbuf_len) {
        ngx_int_t rc = brix_proxy_flush(proxy);
        if (rc == NGX_ERROR) {
            brix_proxy_abort(proxy, "proxy: upstream write error");
            return;
        }
        if (rc == NGX_AGAIN) {
            /* Phase 39 (PXY-2): still draining to a slow/backpressured upstream.
             * Arm/refresh the write-stall deadline (reset each write event, so it
             * fires only after proxy_write_timeout with no progress).  wev->timedout
             * above aborts cleanly.  Off (0) leaves the legacy behaviour. */
            if (proxy->conf != NULL && proxy->conf->proxy.write_timeout > 0) {
                ngx_add_timer(uconn->write, proxy->conf->proxy.write_timeout);
            }
            return;
        }
    }

    /* Upstream write fully drained — clear any write-stall deadline. */
    if (uconn->write->timer_set) {
        ngx_del_timer(uconn->write);
    }

    /* Phase 39 (PXY-3): the deferred send has fully completed — release the write
     * buffer here exactly as the immediate-completion path in forward_request.c
     * does.  Without this a backpressured (slow-consumer) request leaked its raw
     * heap buffer on EVERY request.  No-op / pool-detach for bootstrap frames. */
    brix_proxy_wbuf_release(proxy);

    /* Write complete — arm upstream read */
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                  "xrootd proxy: write done, arming read (state=%d)",
                  (int) proxy->state);
    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        brix_proxy_abort(proxy, "proxy: read arm failed after write");
    }
}

