#include "handshake.h"

/*
 * brix_dispatch_session_opcode — phase 2 of request routing (from
 * handshake/dispatch.c): a switch on ctx->cur_reqid over the seven session
 * lifecycle opcodes — kXR_protocol, kXR_login, kXR_auth, kXR_ping, kXR_set
 * (login-gated), kXR_endsess, kXR_bind — each delegating to its handler (defined
 * in its own module, documented there). These establish the session (protocol
 * version, identity, auth, sessid) before any file I/O. kXR_bind is special: it
 * arrives on a secondary connection before login and must be handled first so the
 * channel knows its parent session. Returns the handler result, or
 * BRIX_DISPATCH_CONTINUE when the opcode is not a session opcode (the read/write
 * dispatchers then try it).
 */
ngx_int_t
brix_dispatch_session_opcode(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    switch (ctx->cur_reqid) {

    case kXR_protocol:
        return brix_handle_protocol(ctx, c, conf);

    case kXR_login:
        return brix_handle_login(ctx, c, conf);

    case kXR_auth:
        return brix_handle_auth(ctx, c);

    case kXR_ping: {
        /* The reference auth gate rejects EVERY non-auth request before login,
         * kXR_ping included (a pre-login ping is not a liveness probe a stock
         * server answers).  Match that — ping requires a completed login. */
        ngx_int_t rc = brix_dispatch_require_login(ctx, c);
        if (rc != BRIX_DISPATCH_CONTINUE) { return rc; }
        return brix_handle_ping(ctx, c);
    }

    case kXR_set: {
        ngx_int_t rc = brix_dispatch_require_login(ctx, c);
        if (rc != BRIX_DISPATCH_CONTINUE) { return rc; }
        return brix_handle_set(ctx, c);
    }

    case kXR_endsess:
        return brix_handle_endsess(ctx, c);

    case kXR_bind:
        /* kXR_bind arrives on secondary connections before kXR_login.
         * It must be dispatched before the login/auth guard below. */
        return brix_handle_bind(ctx, c, conf);

    default:
        return BRIX_DISPATCH_CONTINUE;
    }
}
