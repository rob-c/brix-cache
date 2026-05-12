#include "handshake.h"
#include "../read/clone.h"

static ngx_int_t
xrootd_reject_bound_nonread_file_op(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb)
{
    if (!ctx->is_bound) {
        return XROOTD_DISPATCH_CONTINUE;
    }

    xrootd_log_access(ctx, c, verb, "-", "bound",
                      0, kXR_NotAuthorized,
                      "bound streams may only read primary handles", 0);
    return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                             "bound streams may only read primary handles");
}

ngx_int_t
xrootd_dispatch_read_opcode(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_int_t rc;

    switch (ctx->cur_reqid) {

    case kXR_stat:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "STAT");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_stat(ctx, c, conf);

    case kXR_open:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "OPEN");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_open(ctx, c, conf);

    case kXR_read:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_read(ctx, c);

    case kXR_close:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "CLOSE");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_close(ctx, c);

    case kXR_dirlist:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "DIRLIST");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_dirlist(ctx, c, conf);

    case kXR_readv:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_readv(ctx, c);

    case kXR_query:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "QUERY");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_query(ctx, c, conf);

    case kXR_prepare:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "PREPARE");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_prepare(ctx, c, conf);

    case kXR_pgread:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_pgread(ctx, c);

    case kXR_locate:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "LOCATE");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_locate(ctx, c, conf);

    case kXR_statx:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "STATX");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_statx(ctx, c, conf);

    case kXR_fattr:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "FATTR");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_fattr(ctx, c, conf);

    case kXR_clone:
        rc = xrootd_dispatch_require_auth(ctx, c);
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        rc = xrootd_reject_bound_nonread_file_op(ctx, c, "CLONE");
        if (rc != XROOTD_DISPATCH_CONTINUE) {
            return rc;
        }
        return xrootd_handle_clone(ctx, c);

    default:
        return XROOTD_DISPATCH_CONTINUE;
    }
}
