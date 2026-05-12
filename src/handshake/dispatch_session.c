#include "handshake.h"

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
