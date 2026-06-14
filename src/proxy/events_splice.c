#include "proxy_internal.h"
#include "../connection/handler.h"
#include <sys/socket.h>

/* ---- zero-copy splice fast-path ------------------------------------------ */

#ifdef __linux__

/* Forward declaration — xrootd_proxy_splice_wev is defined after the pump. */
static void xrootd_proxy_splice_wev(ngx_event_t *wev);

/*
 * xrootd_proxy_splice_done — called when all splice_total bytes have been
 * moved from the upstream socket to the client socket.  Mirrors the
 * post-relay accounting that relay_to_client() does for reads.
 */
static void
xrootd_proxy_splice_done(xrootd_proxy_ctx_t *proxy)
{
    xrootd_ctx_t     *ctx    = proxy->client_ctx;
    ngx_connection_t *c      = proxy->client_conn;
    uint16_t          status = proxy->resp_status;
    size_t            dlen   = proxy->splice_total;
    int               lfh    = proxy->fwd_local_fh;

    /* Restore the normal client write handler (may have been changed for EAGAIN). */
    c->write->handler = ngx_stream_xrootd_send;

    /* Per-handle and aggregate byte metrics. */
    if (lfh >= 0 && lfh < XROOTD_MAX_FILES) {
        proxy->fh_map[lfh].bytes_read += dlen;
    }
    XROOTD_PROXY_METRIC_INC(ctx, reads_total);
    XROOTD_PROXY_METRIC_ADD(ctx, read_bytes_total, dlen);
    XROOTD_PROXY_UP_INC(proxy, reads_total);
    XROOTD_PROXY_UP_ADD(proxy, read_bytes_total, dlen);

    /* Reset accumulator for the next response. */
    proxy->splice_active     = 0;
    proxy->splice_total      = 0;
    proxy->splice_upstream   = 0;
    proxy->splice_downstream = 0;
    proxy->rhdr_pos          = 0;
    proxy->resp_dlen         = 0;
    proxy->resp_body         = NULL;
    proxy->resp_body_pos     = 0;

    if (status == kXR_oksofar) {
        proxy->fwd_streaming = 1;
        /*
         * nginx uses edge-triggered epoll.  The upstream socket may already
         * have the trailing kXR_ok(0) frame buffered, but no new edge event
         * will fire for it.  Ensure the read handler is posted so it runs
         * again regardless of whether new data has arrived.
         */
        {
            ngx_event_t *urev = proxy->conn->read;
            if (!urev->active && !urev->ready) {
                if (ngx_handle_read_event(urev, 0) != NGX_OK) {
                    xrootd_proxy_abort(proxy,
                        "proxy: read arm failed after splice oksofar");
                    return;
                }
            }
            if (!urev->posted) {
                ngx_post_event(urev, &ngx_posted_events);
            }
        }
        return;
    }

    /* Final response — hand control back to the client loop. */
    proxy->state = XRD_PX_IDLE;
    ctx->state   = XRD_ST_REQ_HEADER;
    xrootd_schedule_read_resume(c);
}

/*
 * xrootd_proxy_splice_pump — drive splice transfers between upstream socket
 * and client socket via the kernel pipe in proxy->splice_pipe[].
 *
 * Called from:
 *   xrootd_proxy_read_handler  — upstream socket is readable
 *   xrootd_proxy_splice_wev    — client socket is writable (drain pipe)
 */
void
xrootd_proxy_splice_pump(xrootd_proxy_ctx_t *proxy)
{
    ngx_connection_t *uconn = proxy->conn;
    ngx_connection_t *cconn = proxy->client_conn;

    if (uconn == NULL || cconn == NULL) {
        return;
    }

    for (;;) {
        /* ---- upstream fd → pipe[1] ---- */
        if (proxy->splice_upstream < proxy->splice_total) {
            size_t in_pipe_now = proxy->splice_upstream - proxy->splice_downstream;
            if (in_pipe_now == 0) {
                /*
                 * Pipe is empty — safe to fill from upstream.
                 * When in_pipe_now > 0 the pipe is full; attempting
                 * splice(upstream→pipe) would return EAGAIN for the wrong
                 * reason (pipe capacity, not upstream readiness) and we
                 * would arm the upstream-read event prematurely.  Instead,
                 * fall through and drain the pipe to the client first.
                 */
                size_t   want = proxy->splice_total - proxy->splice_upstream;
                ssize_t  r    = splice(uconn->fd, NULL,
                                       proxy->splice_pipe[1], NULL,
                                       want,
                                       SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (r > 0) {
                    proxy->splice_upstream += (size_t) r;
                } else if (r < 0 && ngx_errno == NGX_EAGAIN) {
                    /* Upstream socket empty — arm read and wait. */
                    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
                        xrootd_proxy_abort(proxy,
                            "proxy: splice read arm failed");
                    }
                    return;
                } else if (r == 0) {
                    /* Upstream closed during splice (peer sent FIN). */
                    xrootd_proxy_abort(proxy,
                        "proxy: upstream closed during splice");
                    return;
                } else {
                    xrootd_proxy_abort(proxy,
                        "proxy: splice upstream→pipe failed");
                    return;
                }
            }
        }

        /* ---- pipe[0] → client fd ---- */
        {
            size_t  in_pipe = proxy->splice_upstream - proxy->splice_downstream;
            if (in_pipe == 0) {
                if (proxy->splice_downstream >= proxy->splice_total) {
                    break;
                }
                continue;
            }

            ssize_t r = splice(proxy->splice_pipe[0], NULL,
                               cconn->fd, NULL,
                               in_pipe,
                               SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (r > 0) {
                proxy->splice_downstream += (size_t) r;
            } else if (r == 0 || (r < 0 && ngx_errno == NGX_EAGAIN)) {
                /*
                 * Client send buffer full.  Arm the client-write event and
                 * wait.  Do NOT arm upstream-read here: any unread upstream
                 * data sits in the kernel TCP receive buffer and will be
                 * drained by splice_pump (via splice(upstream→pipe)) once
                 * the pipe has room — no epoll wakeup required for that.
                 * Arming upstream-read while the pipe is full just causes
                 * spurious wakeups that retry a full pipe and deadlock.
                 */
                cconn->write->handler = xrootd_proxy_splice_wev;
                if (ngx_handle_write_event(cconn->write, 0) != NGX_OK) {
                    xrootd_proxy_abort(proxy,
                        "proxy: splice client write arm failed");
                    return;
                }
                return;
            } else {
                xrootd_proxy_abort(proxy,
                    "proxy: splice pipe→client failed");
                return;
            }
        }

        if (proxy->splice_downstream >= proxy->splice_total) {
            break;
        }
    }

    xrootd_proxy_splice_done(proxy);
}

/*
 * xrootd_proxy_splice_wev — client write event handler during splice.
 * Replaces ngx_stream_xrootd_send temporarily while draining the pipe.
 */
static void
xrootd_proxy_splice_wev(ngx_event_t *wev)
{
    ngx_connection_t   *cconn = wev->data;
    xrootd_ctx_t       *ctx   = cconn->data;
    xrootd_proxy_ctx_t *proxy;

    if (ctx == NULL || ctx->destroyed) {
        return;
    }
    proxy = ctx->proxy;
    if (proxy == NULL || !proxy->splice_active) {
        /* Splice already finished — restore normal handler and call it. */
        cconn->write->handler = ngx_stream_xrootd_send;
        ngx_stream_xrootd_send(wev);
        return;
    }

    xrootd_proxy_splice_pump(proxy);
}

/*
 * xrootd_proxy_try_splice — attempt to start a zero-copy splice for the
 * current read response.  Returns NGX_OK if splice was started (the caller
 * must NOT allocate resp_body or loop for body data).  Returns NGX_DECLINED
 * if the conditions are not met and the caller should use the normal path.
 */
ngx_int_t
xrootd_proxy_try_splice(xrootd_proxy_ctx_t *proxy)
{
    u_char            hdr[XRD_RESPONSE_HDR_LEN];
    ssize_t           sent;

#if (NGX_SSL)
    /* Splice bypasses the TLS layer — only valid for plain-text connections. */
    if (proxy->conn->ssl != NULL || proxy->client_conn->ssl != NULL) {
        return NGX_DECLINED;
    }
#endif

    if (proxy->state != XRD_PX_FORWARDING) {
        return NGX_DECLINED;
    }
    if (proxy->fwd_reqid != kXR_read && proxy->fwd_reqid != kXR_pgread) {
        return NGX_DECLINED;
    }
    if (proxy->resp_status != kXR_ok && proxy->resp_status != kXR_oksofar) {
        return NGX_DECLINED;
    }
    if (proxy->resp_dlen == 0) {
        return NGX_DECLINED;
    }

    /* Lazy-create the kernel pipe. */
    if (proxy->splice_pipe[0] == -1) {
        if (pipe2(proxy->splice_pipe, O_NONBLOCK) < 0) {
            ngx_log_error(NGX_LOG_WARN, proxy->client_conn->log, ngx_errno,
                          "xrootd proxy: pipe2 failed, using buffered path");
            return NGX_DECLINED;
        }

        /*
         * Enlarge the pipe to 1 MiB (default is 64 KiB).  splice() pumps at most
         * one pipe-buffer per syscall, so a larger pipe cuts the syscall count on
         * big relayed bodies by ~16x.  Best-effort: F_SETPIPE_SZ can fail if it
         * exceeds /proc/sys/fs/pipe-max-size for an unprivileged process, in which
         * case the kernel keeps the default size and splice still works correctly.
         */
        if (fcntl(proxy->splice_pipe[1], F_SETPIPE_SZ, 1 << 20) < 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log,
                           ngx_errno,
                           "xrootd proxy: F_SETPIPE_SZ(1MiB) failed (errno=%d), "
                           "using default pipe size", ngx_errno);
        }
    }

    /* Send the 8-byte response header (with client's stream ID) to the client
     * now, before splicing the body.  This is a small send that almost always
     * completes immediately. */
    xrootd_build_resp_hdr(proxy->fwd_streamid,
                           proxy->resp_status,
                           proxy->resp_dlen,
                           (ServerResponseHdr *)(void *) hdr);

    sent = proxy->client_conn->send(proxy->client_conn, hdr,
                                    XRD_RESPONSE_HDR_LEN);
    if (sent != XRD_RESPONSE_HDR_LEN) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                       "xrootd proxy: splice header send incomplete (%z), "
                       "using buffered path", sent);
        return NGX_DECLINED;
    }

    proxy->splice_active     = 1;
    proxy->splice_total      = proxy->resp_dlen;
    proxy->splice_upstream   = 0;
    proxy->splice_downstream = 0;

    xrootd_proxy_splice_pump(proxy);
    return NGX_OK;
}

#endif /* __linux__ */

