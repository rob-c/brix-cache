#include "handshake.h"
#include "../proxy/proxy.h"

/*
 * Request routing overview
 * ========================
 *
 * xrootd_dispatch() tries each of the four dispatch functions in order.
 * Each returns XROOTD_DISPATCH_CONTINUE if the opcode is not its own;
 * otherwise it handles the request and returns an ngx_int_t result.
 *
 *   dispatch_session.c  — protocol, login, auth, bind, endsess, ping, set
 *   proxy/forward.c     — all post-login opcodes when xrootd_proxy is on
 *   dispatch_read.c     — open(read), stat, statx, read, readv, pgread,
 *                         close, dirlist, locate, query, prepare
 *   dispatch_write.c    — open(write), write, pgwrite, writev, sync,
 *                         truncate, mkdir, rm, rmdir, mv, chmod, fattr,
 *                         clone, chkpoint
 *   dispatch_signing.c  — sigver (must be last; inspects every request)
 *
 * Adding a new opcode: determine its category above, add a case to the
 * matching dispatch_*.c file, then see docs/contributing.md §5 for the
 * full checklist.
 */

ngx_int_t
xrootd_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_int_t rc;

    /* Every dispatched request resets the per-request timing origin for logging. */
    ctx->req_start = ngx_current_msec;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: dispatch reqid=%d", (int) ctx->cur_reqid);

    rc = xrootd_verify_pending_sigver(ctx, c);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    rc = xrootd_dispatch_session_opcode(ctx, c, conf);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    /* Proxy mode: all post-login file-system opcodes go to the upstream */
    if (conf->proxy_enable && ctx->logged_in) {
        return xrootd_proxy_dispatch(ctx, c, conf);
    }

    rc = xrootd_dispatch_read_opcode(ctx, c, conf);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    rc = xrootd_dispatch_write_opcode(ctx, c, conf);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    rc = xrootd_dispatch_signing_opcode(ctx, c);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: unsupported request %d",
                   (int) ctx->cur_reqid);
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "request not supported");
}
