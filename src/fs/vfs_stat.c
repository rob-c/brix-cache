/*
 * vfs_stat.c — VFS path stat.
 *
 * WHAT: Implements xrootd_vfs_stat(), which lstat()s the resolved ctx path and
 *       fills an xrootd_vfs_stat_t (size/mtime/ctime/mode/ino plus the
 *       is_directory / is_regular flags).
 *
 * WHY:  kXR_stat / kXR_statx, WebDAV PROPFIND on a single resource, and S3 HEAD
 *       all need one confined, metered stat with consistent error mapping
 *       instead of each protocol calling stat(2) directly.
 *
 * HOW:  Re-verifies confinement (and a non-NULL stat_out), uses lstat() so
 *       symlinks are reported rather than followed, converts via
 *       xrootd_vfs_fill_stat(), and emits an XROOTD_METRIC_OP_STAT
 *       metric/access-log line on every path through
 *       xrootd_vfs_observe_ctx_op().
 */
#include "vfs_internal.h"

/* lstat the resolved ctx path into *stat_out (no symlink follow). Confined and
 * metered as OP_STAT; NGX_ERROR with errno set on guard failure or lstat error. */
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

    /*
     * Stat AS THE MAPPED USER under impersonation (broker-routed) — otherwise a
     * metadata op (WebDAV HEAD/DELETE/PROPFIND-on-file, kXR_stat/statx, S3 HEAD)
     * whose target sits inside a directory the unprivileged worker cannot
     * traverse (a 0700 user-owned subdir, or a group-restricted 0770 dir the
     * mapped user reaches only via a supplementary group) would EACCES on a bare
     * lstat and fail (500) for the legitimate owner/group-member.  nofollow=1
     * keeps lstat semantics (report symlinks, never follow).  Off impersonation
     * this is the same bare lstat. */
    if (xrootd_lstat_confined_canon(ctx->log, ctx->root_canon, path, &st, 1) != 0) {
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
