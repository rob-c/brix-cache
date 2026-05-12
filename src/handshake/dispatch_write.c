#include "handshake.h"
#include "../write/chkpoint.h"

ngx_int_t
xrootd_dispatch_write_opcode(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_int_t rc;

    switch (ctx->cur_reqid) {

    case kXR_write:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_write(ctx, c);

    case kXR_pgwrite:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_pgwrite(ctx, c);

    case kXR_sync:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_sync(ctx, c);

    case kXR_truncate:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_truncate(ctx, c, conf);

    case kXR_mkdir:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_mkdir(ctx, c, conf);

    case kXR_rm:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_rm(ctx, c, conf);

    case kXR_writev:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_writev(ctx, c);

    case kXR_rmdir:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_rmdir(ctx, c, conf);

    case kXR_mv:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_mv(ctx, c, conf);

    case kXR_chmod:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_chmod(ctx, c, conf);

    case kXR_chkpoint:
        rc = xrootd_dispatch_require_write(ctx, c, conf);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_chkpoint(ctx, c, conf);

    default:
        return XROOTD_DISPATCH_CONTINUE;
    }
}
