#include "vfs_internal.h"

ngx_int_t
xrootd_vfs_stat(xrootd_vfs_ctx_t *ctx, xrootd_vfs_stat_t *stat_out)
{
    struct stat  st;
    const char  *path;
    ngx_msec_t   start;
    int          saved_errno;

    start = ngx_current_msec;
    path = xrootd_vfs_ctx_path(ctx);

    if (stat_out == NULL || xrootd_vfs_require_confined(ctx) != NGX_OK) {
        errno = EINVAL;
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_STAT, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (lstat(path, &st) != 0) {
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_STAT, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    xrootd_vfs_fill_stat(&st, stat_out);
    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_STAT, NULL, 0,
                              NGX_OK, 0, start);
    return NGX_OK;
}
