/*
 * vfs_unlink.c — VFS delete family (unlink / rmdir).
 *
 * WHAT: Implements xrootd_vfs_unlink() (remove a regular file) and
 *       xrootd_vfs_rmdir() (remove a directory, recursively or only when empty),
 *       both thin wrappers over the shared xrootd_vfs_delete() helper.
 *
 * WHY:  Deletes are write-gated and must be applied through the namespace layer
 *       (../compat/namespace_ops) so confinement and the recursive / require-
 *       empty semantics match the rest of the namespace mutators, with one
 *       metric/access-log emission per call.
 *
 * HOW:  xrootd_vfs_delete() enforces xrootd_vfs_require_write() and a non-NULL
 *       root_canon, builds an xrootd_ns_delete_opts_t (recursive,
 *       require_empty_dir), and calls xrootd_ns_delete(); the namespace status
 *       is mapped back to errno (sys_errno or EIO) and observed as
 *       XROOTD_METRIC_OP_DELETE. rmdir requests require_empty_dir only when not
 *       recursive.
 */
#include "vfs_internal.h"

/* Shared delete body for unlink/rmdir: write-gate, then xrootd_ns_delete with
 * the given recursive / require_empty_dir options; metered as OP_DELETE. */
static ngx_int_t
xrootd_vfs_delete(xrootd_vfs_ctx_t *ctx, unsigned recursive,
    unsigned require_empty_dir)
{
    xrootd_ns_delete_opts_t opts;
    xrootd_ns_result_t      res;
    const char             *path;
    uint64_t                start;
    int                     saved_errno;

    start = xrootd_vfs_now_ns();
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

    errno = res.sys_errno != 0 ? res.sys_errno
                               : xrootd_vfs_ns_status_errno(res.status);
    saved_errno = errno;
    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DELETE, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}

/* Remove a single regular file (non-recursive, no empty-dir requirement). */
ngx_int_t
xrootd_vfs_unlink(xrootd_vfs_ctx_t *ctx)
{
    return xrootd_vfs_delete(ctx, 0, 0);
}

/* Remove a directory: recursively when `recursive`, otherwise only if empty. */
ngx_int_t
xrootd_vfs_rmdir(xrootd_vfs_ctx_t *ctx, unsigned recursive)
{
    return xrootd_vfs_delete(ctx, recursive, recursive ? 0 : 1);
}
