#include "proxy_internal.h"
#include <netdb.h>
#include <sys/socket.h>

/*
 * WHAT: Upstream connection lifecycle helpers — write buffer flush, error abort with reconnect budget, and full resource cleanup.
 * WHY: The transparent XRootD proxy must manage upstream TCP connections carefully: flushing buffered requests atomically to the socket;
 *      handling errors gracefully (reconnect if idle + no open files + budget available); releasing all resources on session teardown including
 *      file handle audit, splice pipe closure, connection pool return. INVARIANT: reconnect attempts tracked in proxy->reconnect_left per-connection;
 *      only triggers when XRD_PX_IDLE state and all upstream handles are closed (not 255=pending).
 * HOW: flush() loops until wbuf_pos reaches wbuf_len; returns NGX_AGAIN/NGX_ERROR for partial send. abort() logs error, checks reconnect conditions,
 *      attempts xrootd_proxy_connect() if eligible, falls through to hard abort on failure or ineligible state. cleanup() audits abandoned handles via proxy_write_audit,
 *      frees resp_body/saved_req/wait_retry_req, deletes timers, closes splice pipe and upstream connection (or returns to pool if idle).
 */

/* ---- public API: xrootd_proxy_flush() — write buffer flush to upstream socket ----
 * WHAT: Flush all buffered request data to the upstream TCP socket via uconn->send loop.
 * WHY: The proxy buffers client requests before writing them to upstream; this function drains the complete buffer atomically. */

/* ---- public API: xrootd_proxy_abort() — upstream error handling with reconnect budget ----
 * WHAT: Handle upstream errors — log, audit failed state via xrootd_proxy_up_mark_failed(), and optionally reconnect if idle + no open files + budget available.
 * WHY: Transparent proxy must recover gracefully from transient upstream drops without terminating client sessions unnecessarily. Reconnect only triggers when idle (no active transfers)
 *      and all file handles are closed — prevents interrupting ongoing read/write operations during recovery attempts. */

/* ---- public API: xrootd_proxy_cleanup() — full resource cleanup on session teardown ----
 * WHAT: Release all proxy resources — audit abandoned open file handles via proxy_write_audit, free buffers/timers/splice pipe/redirect host data, close or pool-return upstream connection.
 * WHY: Session teardown must be comprehensive to prevent resource leaks (file handle leaks cause kXR_IOError downstream; splice pipes leak FDs). Idle connections with no open files are returned to pool for reuse. */

/* ---- flush wbuf to upstream socket --------------------------------------- */

ngx_int_t
xrootd_proxy_flush(xrootd_proxy_ctx_t *proxy)
{
    ngx_connection_t *uconn = proxy->conn;
    ssize_t           n;

    while (proxy->wbuf_pos < proxy->wbuf_len) {
        n = uconn->send(uconn,
                        proxy->wbuf + proxy->wbuf_pos,
                        proxy->wbuf_len - proxy->wbuf_pos);
        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }
        if (n < 0) {
            return NGX_ERROR;
        }
        proxy->wbuf_pos += (size_t) n;
    }

    return NGX_OK;
}

/* ---- abort on upstream error --------------------------------------------- */

void
xrootd_proxy_abort(xrootd_proxy_ctx_t *proxy, const char *reason)
{
    xrootd_ctx_t     *ctx = proxy->client_ctx;
    ngx_connection_t *c   = proxy->client_conn;
    int               i;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_proxy_cleanup(proxy);
        return;
    }

    /*
     * Reconnect if the upstream dropped while idle and no files are open.
     * The reconnect budget is per-connection and resets when a new upstream
     * bootstrap completes successfully.
     */
    if (proxy->state == XRD_PX_IDLE
        && proxy->conf != NULL
        && proxy->reconnect_left > 0)
    {
        /* Only reconnect when all upstream file handles are already closed */
        int has_open = 0;
        for (i = 0; i < XROOTD_MAX_FILES; i++) {
            if (proxy->fh_map[i].upstream_fh != XROOTD_PROXY_FH_FREE
                && proxy->fh_map[i].upstream_fh != 255)
            {
                has_open = 1;
                break;
            }
        }

        if (!has_open) {
            proxy->reconnect_left--;
            XROOTD_PROXY_METRIC_INC(ctx, reconnects_total);
            XROOTD_PROXY_UP_INC(proxy, reconnects_total);
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd proxy: upstream dropped while idle, "
                          "reconnecting (%d attempt(s) left): %s",
                          proxy->reconnect_left, reason);

            /* Close the stale upstream connection but keep the proxy ctx */
            if (proxy->conn != NULL) {
                ngx_close_connection(proxy->conn);
                proxy->conn = NULL;
            }
            if (proxy->resp_body != NULL) {
                ngx_free(proxy->resp_body);
                proxy->resp_body = NULL;
            }
            if (proxy->saved_req != NULL) {
                ngx_free(proxy->saved_req);
                proxy->saved_req = NULL;
            }

            /* Reset upstream state for a fresh bootstrap */
            proxy->state         = XRD_PX_CONNECTING;
            proxy->bs_phase      = XRD_PX_BS_HANDSHAKE;
            proxy->rhdr_pos      = 0;
            proxy->resp_dlen     = 0;
            proxy->resp_body_pos = 0;
            proxy->fwd_local_fh             = -1;
            proxy->fwd_streaming            = 0;
            proxy->fwd_is_lazy_open         = 0;
            proxy->lazy_open_pending_count  = 0;

            if (xrootd_proxy_connect(proxy, c, proxy->conf) == NGX_OK) {
                /* Client stays in XRD_ST_REQ_HEADER — reconnect in progress */
                return;
            }

            /* connect() failed — fall through to hard abort */
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "xrootd proxy: reconnect failed, aborting session");
        }
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "xrootd proxy: upstream error: %s", reason);

    xrootd_proxy_up_mark_failed(proxy);

    ctx->state = XRD_ST_REQ_HEADER;
    xrootd_proxy_cleanup(proxy);
    ctx->proxy = NULL;

    xrootd_send_error(ctx, c, kXR_IOError, reason);
    xrootd_schedule_read_resume(c);
}

/* ---- cleanup ------------------------------------------------------------- */

void
xrootd_proxy_cleanup(xrootd_proxy_ctx_t *proxy)
{
    int i;

    if (proxy == NULL) {
        return;
    }

    /* Count and audit abandoned open file handles */
    if (proxy->client_ctx != NULL) {
        for (i = 0; i < XROOTD_MAX_FILES; i++) {
            if (proxy->fh_map[i].upstream_fh != XROOTD_PROXY_FH_FREE
                && proxy->fh_map[i].upstream_fh != 255 /* pending open */)
            {
                proxy_write_audit(proxy, i);
                XROOTD_PROXY_METRIC_INC(proxy->client_ctx,
                                        abandoned_handles_total);
                XROOTD_PROXY_UP_INC(proxy, abandoned_handles_total);
                proxy->fh_map[i].upstream_fh = XROOTD_PROXY_FH_FREE;
            }
        }
    }

    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }

    /* Phase 39 (PXY-3): free a heap-owned in-flight write buffer that was still
     * pending at teardown/abort (e.g. an aborted forwarded request).  NULL-safe
     * and owned-gated, so a pool-allocated bootstrap frame is merely detached. */
    xrootd_proxy_wbuf_release(proxy);

    if (proxy->saved_req != NULL) {
        ngx_free(proxy->saved_req);
        proxy->saved_req = NULL;
    }

    if (proxy->wait_ev.timer_set) {
        ngx_del_timer(&proxy->wait_ev);
    }
    if (proxy->wait_retry_req != NULL) {
        ngx_free(proxy->wait_retry_req);
        proxy->wait_retry_req = NULL;
    }

    if (proxy->redirect_host.data != NULL) {
        ngx_free(proxy->redirect_host.data);
        proxy->redirect_host.data = NULL;
        proxy->redirect_host.len  = 0;
    }

    if (proxy->splice_pipe[0] != -1) {
        close(proxy->splice_pipe[0]);
        close(proxy->splice_pipe[1]);
        proxy->splice_pipe[0] = -1;
        proxy->splice_pipe[1] = -1;
    }

    if (proxy->conn != NULL) {
        /*
         * If the connection is idle (no open files) and the session was
         * successfully bootstrapped, return it to the pool.
         */
        int has_open = 0;
        for (i = 0; i < XROOTD_MAX_FILES; i++) {
            if (proxy->fh_map[i].upstream_fh != XROOTD_PROXY_FH_FREE) {
                has_open = 1;
                break;
            }
        }

        if (!has_open && proxy->state == XRD_PX_IDLE && !proxy->no_pool) {
            xrootd_proxy_pool_put(proxy);
        }

        if (proxy->conn != NULL) {
            /* Null the data pointer before closing so any pending event
             * handlers on the upstream fd see NULL and bail out safely,
             * preventing use-after-free when the client pool is freed. */
            proxy->conn->data = NULL;
            ngx_close_connection(proxy->conn);
            proxy->conn = NULL;
        }
    }
}
