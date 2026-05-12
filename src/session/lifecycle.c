#include "../ngx_xrootd_module.h"
#include "../proxy/proxy.h"
#include "../proxy/proxy_internal.h"

/* kXR_ping - liveness check */
ngx_int_t
xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    /* No state transition here; just account for the request and reply ok. */
    xrootd_log_access(ctx, c, "PING", "-", "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_PING);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* kXR_endsess - client wants to end the session gracefully */
ngx_int_t
xrootd_handle_endsess(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_endsess received");

    /*
     * Proxy mode: fire-and-forget kXR_endsess to the upstream before tearing
     * down the upstream connection.  This allows the upstream to close the
     * session gracefully (record final stats, release slots) rather than
     * treating the subsequent TCP close as an abrupt disconnect.
     * We do not wait for the upstream response — the cleanup that follows is
     * unconditional and correct regardless of whether the send succeeds.
     */
    if (ctx->proxy != NULL) {
        xrootd_proxy_ctx_t *proxy = (xrootd_proxy_ctx_t *) ctx->proxy;

        if (proxy->state == XRD_PX_IDLE && proxy->conn != NULL) {
            u_char frame[XRD_REQUEST_HDR_LEN + 16]; /* hdr + 16-byte sessid */
            ngx_memzero(frame, sizeof(frame));
            {
                uint16_t rid = htons(kXR_endsess);
                ngx_memcpy(frame + 2, &rid, 2);
            }
            proxy->conn->send(proxy->conn, frame, sizeof(frame));
        }
    }

    /*
     * Mirror disconnect cleanup immediately so metrics and open-handle state
     * are settled before the final response is queued.
     * This keeps explicit end-of-session requests aligned with the same cleanup
     * bookkeeping used for timeouts and transport-level disconnects.
     */
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);

    /*
     * SECURITY: clear session-level auth flags so the dispatcher rejects any
     * further requests that the client attempts on this TCP connection.
     * Without this, a client could re-open files and read/write them after
     * kXR_endsess, bypassing the session-end semantics (and, in GSI deployments,
     * bypassing proxy-certificate expiry that triggered the endsess).
     */
    ctx->logged_in = 0;
    ctx->auth_done = 0;

    return xrootd_send_ok(ctx, c, NULL, 0);
}
