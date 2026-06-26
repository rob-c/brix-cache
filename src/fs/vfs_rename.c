/*
 * vfs_rename.c — VFS rename / move.
 *
 * WHAT: Implements xrootd_vfs_rename(), which moves the resolved ctx (source)
 *       path to a caller-supplied, already-resolved destination
 *       xrootd_path_result_t.
 *
 * WHY:  kXR_mv and WebDAV MOVE need a single write-gated, confined rename whose
 *       destination is verified to be inside the export root before the syscall,
 *       with one metric/access-log line — not an ad-hoc rename(2) per protocol.
 *
 * HOW:  Enforces xrootd_vfs_require_write(), then demands a non-NULL root_canon
 *       and a destination that is itself is_confined with a non-empty resolved
 *       path. It delegates the actual move to xrootd_ns_rename() (namespace
 *       layer), maps the returned status back to errno (sys_errno or EIO), and
 *       observes the operation as XROOTD_METRIC_OP_RENAME on every path.
 */
#include "vfs_internal.h"

/* Move the resolved ctx source path to the confined destination `dst`.
 * Write-gated; both endpoints must be confined. Metered as OP_RENAME. */
ngx_int_t
xrootd_vfs_rename(xrootd_vfs_ctx_t *ctx, const xrootd_path_result_t *dst)
{
    xrootd_ns_result_t res;
    const char        *path;
    uint64_t           start;
    int                saved_errno;

    start = xrootd_vfs_now_ns();
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
