#include "proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include "core/compat/log_diag.h"
#include <sys/socket.h>

/*
 * Internal control flow for the write handler's staged helpers.
 *
 * WHAT: Three-valued outcome returned by the CONNECTING-state helpers so the
 *      top-level handler can preserve nginx's exact early-return semantics.
 * WHY: Event handlers must not reorder send/close or block; each stage either
 *      demands an immediate `return` (fatal or handshake-parked), signals it
 *      already returned control (TLS parked), or lets the handler proceed to
 *      the flush stage.  Encoding this as an enum keeps the caller a flat
 *      early-return ladder with no goto.
 * HOW: PW_DONE => handler must return now; PW_CONTINUE => fall through to flush.
 */
typedef enum {
    PW_CONTINUE = 0,   /* proceed to the flush/complete stage */
    PW_DONE            /* stage finished the handler; return immediately */
} brix_pw_outcome_t;

/*
 * WHAT: Validate the just-completed TCP connect() by reading SO_ERROR, and, on
 *      failure, emit diagnostics, bump connect-error metrics, and abort.
 * WHY: A non-blocking connect() reports its result via the first write event;
 *      getsockopt(SO_ERROR) is the only correct place to detect a refused or
 *      unreachable backend before we start speaking the protocol.
 * HOW: On error return PW_DONE (caller returns after having aborted); on
 *      success delete the connect-timeout timer and return PW_CONTINUE.  Exact
 *      abort ordering (diag -> metrics -> abort) is preserved from the original.
 */
static brix_pw_outcome_t
brix_proxy_check_connect(ngx_connection_t *uconn, brix_proxy_ctx_t *proxy,
    brix_ctx_t *ctx)
{
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
        return PW_DONE;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                   "xrootd proxy: upstream TCP connected");

    /* Remove the connect-timeout timer — it must not fire during normal use. */
    if (uconn->write->timer_set) {
        ngx_del_timer(uconn->write);
    }

    return PW_CONTINUE;
}

#if (NGX_SSL)
/*
 * WHAT: Establish an outbound client TLS connection on the upstream socket,
 *      set SNI, arm the handshake-done handler, and drive the first handshake.
 * WHY: When the upstream is configured for TLS the handshake must begin right
 *      after TCP connect and before any protocol bytes; the SSL layer then
 *      owns the socket until it calls back into brix_proxy_tls_handshake_done.
 * HOW: On ngx_ssl_create_connection failure bump metrics + abort and return
 *      PW_DONE.  On success move to XRD_PX_TLS_HANDSHAKE and, if the handshake
 *      does not park with NGX_AGAIN, invoke the done callback synchronously.
 *      Always returns PW_DONE: the handler must not fall through to flush while
 *      the SSL layer owns the connection.
 */
static brix_pw_outcome_t
brix_proxy_setup_tls(ngx_connection_t *uconn, brix_proxy_ctx_t *proxy,
    brix_ctx_t *ctx)
{
    const char *sni;

    if (ngx_ssl_create_connection(proxy->conf->proxy.tls_ctx, uconn,
                                  NGX_SSL_BUFFER | NGX_SSL_CLIENT)
        != NGX_OK)
    {
        BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_abort(proxy, "proxy: TLS setup failed");
        return PW_DONE;
    }

    /* SNI: prefer explicit name directive, fall back to configured host */
    sni = (proxy->conf->proxy.upstream_tls_name.len > 0)
        ? (const char *) proxy->conf->proxy.upstream_tls_name.data
        : (const char *) proxy->conf->proxy.host.data;
    SSL_set_tlsext_host_name(uconn->ssl->connection, sni);

    uconn->ssl->handler = brix_proxy_tls_handshake_done;
    proxy->state = XRD_PX_TLS_HANDSHAKE;
    if (ngx_ssl_handshake(uconn) != NGX_AGAIN) {
        brix_proxy_tls_handshake_done(uconn);
    }
    return PW_DONE;
}
#endif

#if (NGX_SSL)
/*
 * WHAT: Determine whether the upstream is configured for TLS on this proxy.
 * WHY: Isolates the multi-clause NGX_SSL guard so the connecting-state handler
 *      stays a flat, readable early-return ladder.
 * HOW: True only when conf is present, upstream_tls is on, and a TLS context
 *      was built.  Only compiled in SSL-enabled builds, where it is called.
 */
static ngx_int_t
brix_proxy_upstream_tls_wanted(brix_proxy_ctx_t *proxy)
{
    return proxy->conf != NULL
        && proxy->conf->proxy.upstream_tls
        && proxy->conf->proxy.tls_ctx != NULL;
}
#endif

/*
 * WHAT: Handle the XRD_PX_CONNECTING state: validate the connect, optionally
 *      begin TLS, otherwise transition into the protocol bootstrap phase.
 * WHY: The first write event after connect() is special — it must confirm TCP
 *      connectivity and route into either the TLS handshake (SSL-owned) or the
 *      cleartext bootstrap before any buffered bytes are flushed.
 * HOW: Run connect validation; if TLS is wanted delegate to setup (which parks
 *      the handler); otherwise set BOOTSTRAP/HANDSHAKE state and return
 *      PW_CONTINUE so the caller proceeds to flush.  Propagates PW_DONE from
 *      any sub-stage that already returned control to the event loop.
 */
static brix_pw_outcome_t
brix_proxy_handle_connecting(ngx_connection_t *uconn, brix_proxy_ctx_t *proxy,
    brix_ctx_t *ctx)
{
    if (brix_proxy_check_connect(uconn, proxy, ctx) == PW_DONE) {
        return PW_DONE;
    }

#if (NGX_SSL)
    if (brix_proxy_upstream_tls_wanted(proxy)) {
        return brix_proxy_setup_tls(uconn, proxy, ctx);
    }
#endif

    proxy->state    = XRD_PX_BOOTSTRAP;
    proxy->bs_phase = XRD_PX_BS_HANDSHAKE;
    proxy->rhdr_pos = 0;
    return PW_CONTINUE;
}

/*
 * WHAT: Flush any still-buffered request bytes to the upstream, handling error
 *      and backpressure outcomes.
 * WHY: A slow/backpressured upstream drains across multiple write events; each
 *      partial flush must (re)arm the write-stall deadline so a stalled peer is
 *      aborted only after proxy_write_timeout with no progress.
 * HOW: Nothing to do when the buffer is already drained -> PW_CONTINUE.  On
 *      NGX_ERROR abort and return PW_DONE.  On NGX_AGAIN refresh the write
 *      timer (when configured) and return PW_DONE.  Full completion falls
 *      through to PW_CONTINUE so the caller finishes the handler.
 */
static brix_pw_outcome_t
brix_proxy_flush_buffered(ngx_connection_t *uconn, brix_proxy_ctx_t *proxy)
{
    ngx_int_t rc;

    if (proxy->wbuf_pos >= proxy->wbuf_len) {
        return PW_CONTINUE;
    }

    rc = brix_proxy_flush(proxy);
    if (rc == NGX_ERROR) {
        brix_proxy_abort(proxy, "proxy: upstream write error");
        return PW_DONE;
    }
    if (rc == NGX_AGAIN) {
        /* Phase 39 (PXY-2): still draining to a slow/backpressured upstream.
         * Arm/refresh the write-stall deadline (reset each write event, so it
         * fires only after proxy_write_timeout with no progress).  wev->timedout
         * in the caller aborts cleanly.  Off (0) leaves the legacy behaviour. */
        if (proxy->conf != NULL && proxy->conf->proxy.write_timeout > 0) {
            ngx_add_timer(uconn->write, proxy->conf->proxy.write_timeout);
        }
        return PW_DONE;
    }

    return PW_CONTINUE;
}

/*
 * WHAT: Finalize a fully-drained upstream write: clear the stall deadline,
 *      release the write buffer, and arm the upstream read event.
 * WHY: Once every byte is out the write-stall timer must be cancelled and the
 *      heap/pool write buffer released (a backpressured request otherwise leaks
 *      it on every request); the response then flows once read is armed.
 * HOW: Delete the write timer if set, release the wbuf, log, and arm the read
 *      event — aborting on failure.  Ordering matches the original immediate-
 *      completion path so behaviour is byte-for-byte identical.
 */
static void
brix_proxy_write_complete(ngx_connection_t *uconn, brix_proxy_ctx_t *proxy)
{
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

/*
 * WHAT: Handle upstream write events — TCP connect validation, TLS handshake initiation (if configured),
 *      buffered data flush to upstream, and read event arming after write completes.
 * WHY: nginx-xrootd proxy buffers client requests before writing them to the upstream XRootD server.
 *      The first write event is special because it must validate TCP connectivity, optionally initiate TLS,
 *      then transition into bootstrap phase for protocol negotiation. Subsequent write events flush the buffer.
 * HOW: Extract uconn and proxy ctx from wev->data; check client destruction/timeout; delegate TLS to SSL layer;
 *      on CONNECTING state delegate to brix_proxy_handle_connecting (connect validation + optional TLS);
 *      then brix_proxy_flush_buffered; finally brix_proxy_write_complete arms the upstream read event.
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

    /* On first write event after connect(), validate + optionally begin TLS */
    if (proxy->state == XRD_PX_CONNECTING) {
        if (brix_proxy_handle_connecting(uconn, proxy, ctx) == PW_DONE) {
            return;
        }
    }

    if (brix_proxy_flush_buffered(uconn, proxy) == PW_DONE) {
        return;
    }

    brix_proxy_write_complete(uconn, proxy);
}
