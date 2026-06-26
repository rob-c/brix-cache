/*
 * vfs_mkdir.c — VFS directory creation.
 *
 * WHAT: Implements xrootd_vfs_mkdir(), which creates the resolved ctx path as a
 *       directory with the given mode, optionally creating missing parent
 *       components (`parents`).
 *
 * WHY:  kXR_mkdir and WebDAV MKCOL need one write-gated, confined mkdir with the
 *       same parent-creation semantics and a single metric/access-log emission
 *       as the other namespace mutators.
 *
 * HOW:  Enforces xrootd_vfs_require_write() and a non-NULL root_canon, then
 *       delegates to xrootd_ns_mkdir() (namespace layer) passing mode and the
 *       parents flag. The namespace status is mapped back to errno (sys_errno or
 *       EIO) and observed as XROOTD_METRIC_OP_MKDIR on every path.
 */
#include "vfs_internal.h"

/* Create the resolved ctx path as a directory (mode), creating parents when
 * `parents`. Write-gated and confined; metered as OP_MKDIR. */
ngx_int_t
xrootd_vfs_mkdir(xrootd_vfs_ctx_t *ctx, mode_t mode, unsigned parents)
{
    xrootd_ns_result_t res;
    const char        *path;
    uint64_t           start;
    int                saved_errno;

    start = xrootd_vfs_now_ns();
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
