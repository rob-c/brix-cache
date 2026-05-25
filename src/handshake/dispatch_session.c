#include "handshake.h"

/* ---- Session phase dispatcher — pre-auth and session lifecycle opcodes ----
 *
 * WHAT: Handles protocol negotiation (kXR_protocol), login (kXR_login), authentication (GSI/token/SSS via kXR_auth),
 *       ping (liveness check kXR_ping), set (server config kXR_set), endsess (graceful termination), and bind (secondary channel).
 *
 * WHY: These opcodes establish the session context — protocol version, authentication method, session ID.
 *      All occur BEFORE any file operations are possible. Session must be complete before read/write dispatchers run. */

/* ---- Protocol negotiation phase (kXR_protocol) ----
 *
 * WHAT: Client and server negotiate capabilities — protocol versions, TLS support, feature flags.
 *       Determines which authentication methods and transport modes the session will use.
 *
 * WHY: Without version negotiation, client and server may disagree on wire format, opcode set,
 *      or TLS upgrade procedure. This prevents malformed responses from incompatible pairs.
 *
 * HOW: Server reads ClientProtocolRequest wire struct → compares protocol_version against
 *      supported range → builds ServerResponseHdr with negotiated version + capability flags
 *      (TLS ability, signing ability) → returns via xrootd_queue_response(). */

/* ---- Login phase (kXR_login) ----
 *
 * WHAT: Establishes session identity by sending username to server, receiving opaque session ID in response.
 *       This is the first authenticated step — creates ctx->sessid for all subsequent operations.
 *
 * WHY: Login is mandatory before any file operation regardless of auth mode. It begins tracking
 *      session-level metrics (bytes_read/written/duration) and in CMS manager mode triggers
 *      server registry registration if not already bound to a data server.
 *
 * HOW: Server reads ClientLoginRequest wire struct → extracts 8-byte username + PID → generates
 *      unique sessid → sets logged_in=1 → branches by auth mode (NONE=sessid-only, GSI/SSS/TOKEN/BOTH=
 *      sessid+parameter block) → registers session in shared registry → queues response. */

/* ---- Authentication phase (kXR_auth) ----
 *
 * WHAT: Client sends authentication credentials (GSI proxy cert, JWT bearer token, or SSS shared secret).
 *       Server validates credentials and returns auth result with capability flags (TLS ability, signing ability).
 *
 * WHY: Login only establishes identity; auth verifies it. Without credential validation the sessid
 *      could belong to anyone — auth gates file operations by actual trust (certificate chain,
 *      JWT signature, shared secret match).
 *
 * HOW: Server reads wire payload → dispatches to GSI cert verification (src/gsi/), token validation
 *      (src/token/), or SSS matching (src/sss/) → builds capability parameter block on success
 *      → returns auth result with flags for kXR_sigver signing ability and TLS upgrade. */

/* ---- Ping/liveness check (kXR_ping) ----
 *
 * WHAT: Simple no-payload request that server must acknowledge. Used to verify connection is still alive.
 *       No authentication required — can be sent on unauthenticated connections for basic liveness checks.
 *
 * WHY: TCP keepalive only detects dead sockets; ping detects dead sessions (e.g., client process
 *      crashed but socket still open). Allows server to reclaim sessid slots and fd handles from
 *      stale clients before timeout expires.
 *
 * HOW: Server reads ClientPingRequest wire struct → verifies ctx exists and is not destroyed →
 *      builds simple ok response with stream ID echo → returns via xrootd_queue_response(). */

/* ---- Server config set (kXR_set) ----
 *
 * WHAT: Client requests to modify server-side configuration option. Requires login (authenticated session).
 *       Used rarely in production — mostly for testing or dynamic reconfiguration scenarios.
 *
 * WHY: Allows administrators to adjust runtime parameters without restarting the server (e.g.,
 *      changing root path, enabling/disabling write access). Provides operational flexibility
 *      during maintenance windows or capacity adjustments.
 *
 * HOW: Server first checks logged_in=1 precondition → reads ClientSetRequest wire struct with
 *      option name/value pair → validates against allowed options list → updates live config field
 *      in srv_conf → returns ok response. Rejects if not logged in or unknown option. */

/* ---- Session termination (kXR_endsess) ----
 *
 * WHAT: Graceful client-initiated session teardown. Server closes all open handles and frees resources.
 *       Unlike unexpected disconnect (handled by src/connection/disconnect.c), this is a controlled shutdown.
 *
 * WHY: Clients may want to end their session cleanly before the TCP connection drops (e.g.,
 *      client process finishing work, switching to another server). Prevents resource leaks
 *      from unclosed handles and frees sessid slot in shared registry for reuse.
 *
 * HOW: Server iterates ctx->files[] closing each open fd → logs access entries for all handles
 *      → unregisters sessid from shared session registry → frees crypto/payload buffers
 *      → decrements connections_active metric → returns ok response. */

/* ---- Secondary channel bind (kXR_bind) — special ordering ----
 *
 * WHAT: Binds a secondary TCP connection to an existing session for parallel stream transfers.
 *       CRITICAL ORDERING: arrives on secondary connections BEFORE kXR_login must be dispatched first,
 *       then authenticated via login/auth below. This ensures the binding happens at the right lifecycle stage.
 *
 * WHY: Native XRootD TPC (data transfer) requires two channels — one for control, one for data.
 *      The secondary channel must know which session it belongs to before login so that file
 *      handles opened on the primary are visible on the secondary without re-opening.
 *
 * HOW: Server reads ClientBindRequest wire struct → extracts parent sessid from payload →
 *      looks up existing ctx in registry by sessid → copies ctx pointer to new connection →
 *      sets is_bound=1 → returns ok response with parent session info. Login/auth then
 *      proceed on the secondary channel using the same credentials. */

/* ---- Dispatcher entry point (dispatch_session_opcode) ----
 *
 * WHAT: Called from src/handshake/dispatch.c as phase 2 of request routing. Tries each session opcode case in order.
 *       Returns XROOTD_DISPATCH_CONTINUE (NGX_DECLINED) if opcode is not a session opcode — passes to read/write dispatchers. */

/* ---- Function: xrootd_dispatch_session_opcode() ----
 *
 * WHAT: Dispatches pre-auth and session lifecycle opcodes from the central dispatcher (src/handshake/dispatch.c). Handles
 *      eight session-level requests: protocol negotiation, login, authentication (GSI/token/SSS), ping/liveness check,
 *      server config set, session termination, and secondary channel binding. Returns XROOTD_DISPATCH_CONTINUE if opcode
 *      is not a session opcode — allowing read/write dispatchers to handle it instead.
 *
 * WHY: Session lifecycle opcodes must be processed before any file I/O operations can occur. This dispatcher ensures
 *      that protocol negotiation, user login, and authentication all complete successfully before the client can open/read files.
 *      The kXR_bind case is special — it arrives on secondary connections before login and must be dispatched first to ensure
 *      proper binding lifecycle ordering.
 *
 * HOW: Single switch statement matching ctx->cur_reqid (opcode) against eight session opcodes → calls corresponding handler function →
 *      returns handler result or XROOTD_DISPATCH_CONTINUE for unhandled cases. kXR_set additionally requires login check before handling. */

ngx_int_t
xrootd_dispatch_session_opcode(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    switch (ctx->cur_reqid) {

    case kXR_protocol:
        return xrootd_handle_protocol(ctx, c, conf);

    case kXR_login:
        return xrootd_handle_login(ctx, c, conf);

    case kXR_auth:
        return xrootd_handle_auth(ctx, c);

    case kXR_ping:
        return xrootd_handle_ping(ctx, c);

    case kXR_set: {
        ngx_int_t rc = xrootd_dispatch_require_login(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; }
        return xrootd_handle_set(ctx, c);
    }

    case kXR_endsess:
        return xrootd_handle_endsess(ctx, c);

    case kXR_bind:
        /* kXR_bind arrives on secondary connections before kXR_login.
         * It must be dispatched before the login/auth guard below. */
        return xrootd_handle_bind(ctx, c, conf);

    default:
        return XROOTD_DISPATCH_CONTINUE;
    }
}
