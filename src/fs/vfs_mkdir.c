#include "vfs_internal.h"

ngx_int_t
xrootd_vfs_mkdir(xrootd_vfs_ctx_t *ctx, mode_t mode, unsigned parents)
{
    xrootd_ns_result_t res;
    const char        *path;
    ngx_msec_t         start;
    int                saved_errno;

    start = ngx_current_msec;
    path = xrootd_vfs_ctx_path(ctx);

    if (xrootd_vfs_require_write(ctx) != NGX_OK) {
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_MKDIR, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (ctx->root_canon == NULL) {
        errno = EINVAL;
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_MKDIR, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    res = xrootd_ns_mkdir(ctx->log, ctx->root_canon,
                          xrootd_vfs_ctx_path(ctx), mode,
                          parents ? 1 : 0);
    if (res.status == XROOTD_NS_OK) {
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_MKDIR, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    errno = res.sys_errno != 0 ? res.sys_errno : EIO;
    saved_errno = errno;
    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_MKDIR, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}
