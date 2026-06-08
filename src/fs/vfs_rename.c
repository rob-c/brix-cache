#include "vfs_internal.h"

ngx_int_t
xrootd_vfs_rename(xrootd_vfs_ctx_t *ctx, const xrootd_path_result_t *dst)
{
    xrootd_ns_result_t res;
    const char        *path;
    ngx_msec_t         start;
    int                saved_errno;

    start = ngx_current_msec;
    path = xrootd_vfs_ctx_path(ctx);

    if (xrootd_vfs_require_write(ctx) != NGX_OK) {
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (ctx->root_canon == NULL || dst == NULL || !dst->is_confined
        || dst->resolved.data == NULL)
    {
        errno = EINVAL;
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    res = xrootd_ns_rename(ctx->log, ctx->root_canon,
                           xrootd_vfs_ctx_path(ctx),
                           (const char *) dst->resolved.data, 0);
    if (res.status == XROOTD_NS_OK) {
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_RENAME, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    errno = res.sys_errno != 0 ? res.sys_errno : EIO;
    saved_errno = errno;
    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_RENAME, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}
