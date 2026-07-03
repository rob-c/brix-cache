/*
 * lifecycle.c — kXR_ping / kXR_endsess opcode handlers (session liveness + teardown).
 */

#include "core/ngx_brix_module.h"
#include "net/proxy/proxy.h"
#include "net/proxy/proxy_internal.h"
#include "registry.h"   /* brix_session_unregister: targeted session teardown */

/* kXR_ping - liveness check */
/* Handle kXR_ping — a no-op liveness check; returns kXR_ok. */
ngx_int_t
brix_handle_ping(brix_ctx_t *ctx, ngx_connection_t *c)
{
    /* No state transition here; just account for the request and reply ok. */
    BRIX_RETURN_OK(ctx, c, BRIX_OP_PING, "PING", "-", "-", 0);
}

/* kXR_endsess - client wants to end the session gracefully */
/* Handle kXR_endsess — the client's explicit request to gracefully terminate
 * its session. */
ngx_int_t
brix_handle_endsess(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ClientEndsessRequest *req = (ClientEndsessRequest *) ctx->hdr_buf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_endsess received");

    /*
     * kXR_endsess names the session to terminate (req.sessid) — which is NOT
     * necessarily the session of the connection it arrives on. The official
     * client's reconnect recovery, after a dropped link, opens a NEW connection,
     * logs in afresh, and THEN sends kXR_endsess for its PREVIOUS (now-dead)
     * session to release it. Per the protocol we must terminate only the NAMED
     * session; tearing down or de-authenticating THIS freshly-authenticated
     * connection would make the client's very next request (its recovery
     * kXR_open) fail with kXR_NotAuthorized — which is exactly what broke
     * official-client transfer recovery against this server on a lossy link.
     *
     * So: if the request names a DIFFERENT session, just unregister that session
     * (idempotent cross-worker cleanup) and leave this connection's auth state
     * and open handles untouched. Only an endsess for THIS connection's own
     * session performs the full teardown + auth clear below.
     */
    if (ngx_memcmp(req->sessid, ctx->sessid, BRIX_SESSION_ID_LEN) != 0) {
        brix_session_unregister(req->sessid);
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: kXR_endsess for a different session — "
                       "released it, this connection stays authenticated");
        return brix_send_ok(ctx, c, NULL, 0);
    }

    /*
     * Proxy mode: fire-and-forget kXR_endsess to the upstream before tearing
     * down the upstream connection.  This allows the upstream to close the
     * session gracefully (record final stats, release slots) rather than
     * treating the subsequent TCP close as an abrupt disconnect.
     * We do not wait for the upstream response — the cleanup that follows is
     * unconditional and correct regardless of whether the send succeeds.
     */
    if (ctx->proxy != NULL) {
        brix_proxy_ctx_t *proxy = (brix_proxy_ctx_t *) ctx->proxy;

        proxy->no_pool = 1;

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
    brix_on_disconnect(ctx, c);
    brix_close_all_files(ctx);

    /*
     * SECURITY: clear session-level auth flags so the dispatcher rejects any
     * further requests that the client attempts on this TCP connection.
     * Without this, a client could re-open files and read/write them after
     * kXR_endsess, bypassing the session-end semantics (and, in GSI deployments,
     * bypassing proxy-certificate expiry that triggered the endsess).
     */
    ctx->logged_in = 0;
    ctx->auth_done = 0;

    return brix_send_ok(ctx, c, NULL, 0);
}
