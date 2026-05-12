#include "handshake.h"

ngx_int_t
xrootd_dispatch_signing_opcode(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_int_t rc;

    if (ctx->cur_reqid != kXR_sigver) {
        return XROOTD_DISPATCH_CONTINUE;
    }

    rc = xrootd_dispatch_require_login(ctx, c);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    return xrootd_handle_sigver(ctx, c);
}
