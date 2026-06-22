#include "../ngx_xrootd_module.h"
#include "../proxy/proxy.h"
#include "../proxy/proxy_internal.h"
#include "registry.h"   /* xrootd_session_unregister: targeted session teardown */

/* ------------------------------------------------------------------ */
/* Session Lifecycle — kXR_ping and kXR_endsess handlers              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements three session-level lifecycle requests that do not
 *       involve any file I/O or namespace operations. They keep the TCP
 *       connection alive (PING) or terminate it cleanly (ENDSESS).
 *
 * WHY: These opcodes are simple but critical for operational health monitoring:
 *      PING is used by clients and proxy gateways to verify that their XRootD
 *      server is responsive. ENDSESS allows a client to explicitly close its
 *      session rather than relying on TCP-level disconnect, which gives us time
 *      to log throughput metrics, release open file handles, and clear auth state.
 *
 * HOW: Both functions return kXR_ok immediately — they are pure bookkeeping ops
 *      with no data transfer involved. ENDSESS additionally performs cleanup:
 *      closing all open files in fd_table.c, resetting logged_in/auth_done flags,
 *      and (in proxy mode) forwarding the endsess signal to the upstream server. */

/* ------------------------------------------------------------------ */
/* Section: Ping — Liveness Check                                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: kXR_ping is a no-op request that simply confirms the server is alive.
 *       Clients send it periodically (typically every 10–30 seconds) to verify
 *       their connection hasn't silently dropped. The handler does nothing but
 *       log the request and return kXR_ok — no state change, no data transfer.
 *
 * WHY: In high-availability deployments where servers may restart or network
 *      partitions occur, clients need a way to detect stale connections before
 *      attempting expensive file operations that would fail anyway.
 *
 * HOW: The handler increments the PING operation counter (XROOTD_OP_PING),
 *      writes an access-log entry with detail "PING" and status 1 (success),
 *      then returns kXR_ok via xrootd_send_ok(). No body payload is required. */

/* ---- Function: xrootd_handle_ping() ----
 *
 * WHAT: Handles the kXR_ping opcode — a simple liveness check that returns ok
 *       without any state transition or data transfer. Called by clients to verify
 *       their connection is still alive with the XRootD server.
 *
 * WHY: Minimal overhead operation used for health monitoring in production deployments.
 *      Clients typically ping every 10–30 seconds; high ping rates may indicate network issues.
 *
 * HOW: Logs access entry → increments PING counter → returns kXR_ok response with no body. */

/* kXR_ping - liveness check */
ngx_int_t
xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    /* No state transition here; just account for the request and reply ok. */
    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_PING, "PING", "-", "-", 0);
}

/* ------------------------------------------------------------------ */
/* Section: End Session — Graceful Termination                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: kXR_endsess is the client's explicit request to terminate its session.
 *       Unlike a TCP-level disconnect (which can happen silently due to network
 *       issues), this opcode gives us structured cleanup time to log metrics,
 *       release all open file handles, and clear authentication state.
 *
 * WHY: In production deployments, especially with GSI certificates that expire,
 *      clients may end their session when their proxy certificate expires rather
 *      than continuing to use stale credentials. We need to enforce this boundary
 *      by clearing auth flags so no further operations are allowed on the connection.
 *
 * HOW: Three-phase cleanup sequence:
 *      1. Proxy forwarding (if enabled): send endsess frame to upstream server
 *         so it can record final stats and release slots gracefully
 *      2. Local cleanup: disconnect handler + close all open file handles
 *      3. Security enforcement: clear logged_in/auth_done flags — dispatcher
 *         will reject any subsequent requests on this TCP connection */

/* ---- Function: xrootd_handle_endsess() ----
 *
 * WHAT: Handles the kXR_endsess opcode — gracefully terminates a client session by:
 *       (1) forwarding endsess to upstream in proxy mode, (2) closing all open files,
 *       (3) clearing authentication state (logged_in=0, auth_done=0), and returning kXR_ok.
 *
 * WHY: Provides structured session cleanup with security enforcement. Without this,
 *      a client could continue file operations after their GSI proxy certificate expired
 *      or they explicitly wanted to end their session — bypassing both session-end semantics
 *      and auth expiry enforcement.
 *
 * HOW: Three-phase sequence → proxy forward (fire-and-forget) → local cleanup (disconnect + close files) →
 *      security clear (logged_in=0, auth_done=0) → return kXR_ok response with no body payload. */

/* kXR_endsess - client wants to end the session gracefully */
ngx_int_t
xrootd_handle_endsess(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientEndsessRequest *req = (ClientEndsessRequest *) ctx->hdr_buf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_endsess received");

    /*
     * kXR_endsess names the session to terminate (req->sessid) — which is NOT
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
    if (ngx_memcmp(req->sessid, ctx->sessid, XROOTD_SESSION_ID_LEN) != 0) {
        xrootd_session_unregister(req->sessid);
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: kXR_endsess for a different session — "
                       "released it, this connection stays authenticated");
        return xrootd_send_ok(ctx, c, NULL, 0);
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
        xrootd_proxy_ctx_t *proxy = (xrootd_proxy_ctx_t *) ctx->proxy;

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
