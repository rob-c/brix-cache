/*
 * vfs_copy.c — VFS single-file copy (server-side COPY / CopyObject).
 *
 * WHAT: Implements brix_vfs_copy() — copy the resolved ctx (source) regular
 *       file to a destination path within the same export root, the data-mover
 *       behind WebDAV COPY and S3 CopyObject.
 *
 * WHY:  The copy engines reached brix_ns_local_copy() (copy_file_range with a
 *       read/write fallback) directly, so the bytes moved were confined but
 *       unmetered. Routing through here books one BRIX_METRIC_OP_COPY metric +
 *       access-log line per copy, with the byte count taken from the resulting
 *       destination size, while still delegating the confined data move to the
 *       namespace layer.
 *
 * HOW:  brix_vfs_copy() write-gates (brix_vfs_require_write — a copy creates
 *       a new object), translates the public brix_vfs_copy_opts_t into an
 *       brix_ns_copy_opts_t, and calls brix_ns_local_copy(ctx->root_canon,
 *       src=ctx path, dst). The namespace status is mapped back to errno and
 *       observed as OP_COPY; bytes are best-effort from a post-copy lstat of the
 *       destination (0 if that stat fails — it never affects the return value).
 */
#include "vfs_internal.h"

/* Copy the resolved ctx source file to dst_resolved (both under ctx->root_canon).
 * Returns NGX_OK, or NGX_ERROR with errno set (mapped from the namespace status:
 * EEXIST when the destination exists and overwrite is unset, EXDEV on a confine-
 * ment escape, EISDIR/ECONFLICT on a directory source). Metered as OP_COPY. */
ngx_int_t
brix_vfs_copy(brix_vfs_ctx_t *ctx, const char *dst_resolved,
    const brix_vfs_copy_opts_t *opts)
{
    brix_ns_copy_opts_t     ns_opts;
    brix_ns_result_t        res;
    const char               *src = brix_vfs_ctx_path(ctx);
    uint64_t                  start = brix_vfs_now_ns();
    size_t                    bytes = 0;
    struct stat               sb;
    int                       saved_errno;
    const brix_sd_driver_t *drv;

    if (brix_vfs_require_write(ctx) != NGX_OK) {
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (ctx->root_canon == NULL || dst_resolved == NULL) {
        errno = EINVAL;
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    /* Non-POSIX backend: copy through the driver's server-copy slot. The opts'
     * overwrite gate is enforced here via a pre-stat (the slot itself replaces). */
    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        const char      *s = brix_vfs_export_relative(ctx, src);
        const char      *d = brix_vfs_export_relative(ctx, dst_resolved);
        off_t            copied = 0;
        ngx_int_t        rc;
        brix_sd_stat_t dst_st;

        if (opts != NULL && !opts->overwrite && drv->stat != NULL
            && drv->stat(ctx->sd, d, &dst_st) == NGX_OK)
        {
            errno = EEXIST;
            brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL, 0,
                                      NGX_ERROR, EEXIST, start);
            return NGX_ERROR;
        }

        rc = (drv->server_copy != NULL)
            ? drv->server_copy(ctx->sd, s, d, &copied)
            : (errno = ENOSYS, NGX_ERROR);
        saved_errno = (rc == NGX_OK) ? 0 : errno;
        brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL,
                                  rc == NGX_OK ? (size_t) copied : 0, rc,
                                  saved_errno, start);
        return rc;
    }

    ngx_memzero(&ns_opts, sizeof(ns_opts));
    if (opts != NULL) {
        ns_opts.recursive       = opts->recursive ? 1 : 0;
        ns_opts.overwrite       = opts->overwrite ? 1 : 0;
        ns_opts.overwrite_dirs  = opts->overwrite_dirs ? 1 : 0;
        ns_opts.preserve_xattrs = opts->preserve_xattrs ? 1 : 0;
        ns_opts.staged_commit   = opts->staged_commit ? 1 : 0;
    }

    res = brix_ns_local_copy(ctx->log, ctx->root_canon, src, dst_resolved,
                               &ns_opts);
    if (res.status != BRIX_NS_OK) {
        errno = res.sys_errno != 0 ? res.sys_errno
                                   : brix_vfs_ns_status_errno(res.status);
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    /* Best-effort byte count for the metric; a stat failure here is non-fatal. */
    if (brix_lstat_confined_canon(ctx->log, ctx->root_canon, dst_resolved,
                                    &sb, 1) == 0
        && S_ISREG(sb.st_mode))
    {
        bytes = (size_t) sb.st_size;
    }

    brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL, bytes,
                              NGX_OK, 0, start);
    return NGX_OK;
}
