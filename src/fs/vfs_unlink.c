#include "vfs_internal.h"

static ngx_int_t
xrootd_vfs_delete(xrootd_vfs_ctx_t *ctx, unsigned recursive,
    unsigned require_empty_dir)
{
    xrootd_ns_delete_opts_t opts;
    xrootd_ns_result_t      res;
    const char             *path;
    ngx_msec_t              start;
    int                     saved_errno;

    start = ngx_current_msec;
    path = xrootd_vfs_ctx_path(ctx);

    if (xrootd_vfs_require_write(ctx) != NGX_OK) {
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DELETE, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (ctx->root_canon == NULL) {
        errno = EINVAL;
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DELETE, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.recursive = recursive ? 1 : 0;
    opts.require_empty_dir = require_empty_dir ? 1 : 0;

    res = xrootd_ns_delete(ctx->log, ctx->root_canon,
                           xrootd_vfs_ctx_path(ctx), &opts);
    if (res.status == XROOTD_NS_OK) {
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DELETE, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    errno = res.sys_errno != 0 ? res.sys_errno : EIO;
    saved_errno = errno;
    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DELETE, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}

ngx_int_t
xrootd_vfs_unlink(xrootd_vfs_ctx_t *ctx)
{
    return xrootd_vfs_delete(ctx, 0, 0);
}

ngx_int_t
xrootd_vfs_rmdir(xrootd_vfs_ctx_t *ctx, unsigned recursive)
{
    return xrootd_vfs_delete(ctx, recursive, recursive ? 0 : 1);
}
