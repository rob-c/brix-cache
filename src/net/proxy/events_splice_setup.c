#include "proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include "protocols/root/connection/write_helpers.h"   /* brix_queue_response_base */
#include <sys/socket.h>
#include <sys/ioctl.h>   /* FIONREAD — only splice a fully-buffered body */
#include <unistd.h>      /* read() — drain pipe residual on a spurious drain EAGAIN */

/* zero-copy splice fast-path — eligibility gate + one-shot setup.
 * Split verbatim out of events_splice.c; the pump it kicks off
 * (brix_proxy_splice_pump) lives in events_splice.c and is prototyped in
 * proxy_internal.h. */
#ifdef __linux__

/*
 * brix_proxy_splice_eligible — WHAT: gate the zero-copy splice fast-path for
 * the current response.  WHY: splice bypasses TLS and is safe only for a final
 * fully-buffered read/pgread body; multi-frame oksofar streams need the buffered
 * relay's ordinary read-loop/event ordering.  HOW: reject TLS, wrong
 * state/opcode/status, empty body, and (via FIONREAD) a body not yet fully in
 * the upstream socket buffer.  Returns 1 if eligible.
 */
static int
brix_proxy_splice_eligible(brix_proxy_ctx_t *proxy)
{
    int avail = 0;

#if (NGX_SSL)
    /* Splice bypasses the TLS layer — only valid for plain-text connections. */
    if (proxy->conn->ssl != NULL || proxy->client_conn->ssl != NULL) {
        return 0;
    }
#endif

    if (proxy->state != XRD_PX_FORWARDING) {
        return 0;
    }
    if (proxy->fwd_reqid != kXR_read && proxy->fwd_reqid != kXR_pgread) {
        return 0;
    }
    if (proxy->resp_status != kXR_ok) {
        return 0;
    }
    if (proxy->resp_dlen == 0) {
        return 0;
    }

    /*
     * Only splice a body that has ALREADY fully arrived in the upstream socket
     * buffer (the 8-byte header was just consumed, so FIONREAD now reports body
     * bytes).  Splicing a still-streaming body makes the pump hit a mid-transfer
     * EAGAIN and hand the remainder to the buffered relay — a fragile transition
     * whose epoll-ET re-arm is unreliable after splice() drains the socket
     * (observed as rare multi-second lost-wakeup stalls into proxy_read_timeout
     * over proxy→proxy hops).  When the whole body is buffered, splice completes
     * in one pump with no handoff; otherwise the caller's buffered relay reads the
     * streamed body reliably (it drains the socket per wakeup and is plenty fast).
     * This keeps zero-copy for the fully-buffered common case while removing the
     * stall-prone streaming-splice handoff entirely.
     */
    if (ioctl(proxy->conn->fd, FIONREAD, &avail) != 0
        || (size_t) avail < (size_t) proxy->resp_dlen) {
        return 0;
    }

    return 1;
}

/*
 * brix_proxy_splice_pipe_ensure — WHAT: lazily create the kernel pipe used as
 * the splice conduit.  WHY: the pipe is per-proxy and only needed on the splice
 * path; a larger pipe cuts syscalls on big bodies.  HOW: pipe2(O_NONBLOCK) once,
 * best-effort F_SETPIPE_SZ(1 MiB).  Returns NGX_OK, or NGX_DECLINED if the pipe
 * could not be created (caller falls back to the buffered path).
 */
static ngx_int_t
brix_proxy_splice_pipe_ensure(brix_proxy_ctx_t *proxy)
{
    if (proxy->splice_pipe[0] != -1) {
        return NGX_OK;
    }

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

    return NGX_OK;
}

/*
 * brix_proxy_splice_send_hdr — WHAT: send the full 8-byte response header (with
 * the client's stream ID) before splicing the body.  WHY (Phase 39 / PXY-6):
 * once ANY header byte is on the wire we must not fall back to the buffered
 * relay — it rebuilds and re-sends the WHOLE header, duplicating bytes and
 * corrupting the client frame stream.  HOW: a bounded send loop —
 *   - nothing sent yet (NGX_AGAIN at off==0): decline → buffered path sends it;
 *   - partial: complete the (<=7-byte) remainder here (bounded, off caps at 8);
 *   - NGX_AGAIN mid-remainder or a socket error: abort cleanly (NGX_ERROR).
 * Returns NGX_OK (fully sent), NGX_DECLINED (nothing sent), or NGX_ERROR
 * (aborted — caller must return immediately without touching `proxy`).
 */
static ngx_int_t
brix_proxy_splice_send_hdr(brix_proxy_ctx_t *proxy)
{
    u_char hdr[XRD_RESPONSE_HDR_LEN];
    size_t off = 0;
    ssize_t sent;

    brix_build_resp_hdr(proxy->fwd_streamid,
                        proxy->resp_status,
                        proxy->resp_dlen,
                        (ServerResponseHdr *)(void *) hdr);

    for ( ;; ) {
        sent = proxy->client_conn->send(proxy->client_conn,
                                        hdr + off,
                                        XRD_RESPONSE_HDR_LEN - off);
        if (sent > 0) {
            off += (size_t) sent;
            if (off == XRD_RESPONSE_HDR_LEN) {
                return NGX_OK;             /* fully sent — proceed to splice */
            }
            continue;                      /* partial — send the remainder */
        }
        if (sent == NGX_AGAIN && off == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                           "xrootd proxy: splice header would block, "
                           "using buffered path");
            return NGX_DECLINED;
        }
        /* NGX_AGAIN after a partial header, or a socket error: cannot fall
         * back without duplicating on-wire bytes, and the splice path has no
         * deferred-header state.  Abort rather than corrupt. */
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                       "xrootd proxy: splice header send incomplete (%z), "
                       "aborting to avoid frame corruption", sent);
        brix_proxy_abort(proxy, "proxy: splice header send incomplete");
        return NGX_ERROR;
    }
}

/*
 * brix_proxy_try_splice — attempt to start a zero-copy splice for the
 * current read response.  Returns NGX_OK if splice was started (the caller
 * must NOT allocate resp_body or loop for body data).  Returns NGX_DECLINED
 * if the conditions are not met and the caller should use the normal path.
 * Returns NGX_ERROR if it had to abort the session (PXY-6 partial-header case);
 * the proxy has been torn down and the caller MUST return immediately without
 * touching `proxy`.
 */
ngx_int_t
brix_proxy_try_splice(brix_proxy_ctx_t *proxy)
{
    ngx_int_t rc;

    if (!brix_proxy_splice_eligible(proxy)) {
        return NGX_DECLINED;
    }

    if (brix_proxy_splice_pipe_ensure(proxy) != NGX_OK) {
        return NGX_DECLINED;
    }

    rc = brix_proxy_splice_send_hdr(proxy);
    if (rc != NGX_OK) {
        return rc;                 /* NGX_DECLINED or NGX_ERROR (aborted) */
    }

    proxy->splice_active     = 1;
    proxy->splice_total      = proxy->resp_dlen;
    proxy->splice_upstream   = 0;
    proxy->splice_downstream = 0;

    brix_proxy_splice_pump(proxy);
    return NGX_OK;
}

#endif /* __linux__ */
