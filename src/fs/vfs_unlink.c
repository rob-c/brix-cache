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

/* xrootd_vfs_driver_rmtree — depth-first delete of `logical` through the storage
 * driver: a file is unlinked directly; a directory has its children removed
 * (opendir/readdir recursion) before the now-empty directory itself. Generic over
 * any driver that implements stat/opendir/readdir/unlink. NGX_OK or NGX_ERROR. */
static ngx_int_t
xrootd_vfs_driver_rmtree(xrootd_vfs_ctx_t *ctx, const xrootd_sd_driver_t *drv,
    const char *logical)
{
    xrootd_sd_stat_t st;

    if (drv->stat == NULL || drv->unlink == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    if (drv->stat(ctx->sd, logical, &st) != NGX_OK) {
        return NGX_ERROR;            /* ENOENT etc. — errno set by the driver */
    }

    if (st.is_dir && drv->opendir != NULL) {
        xrootd_sd_dir_t *dir;
        int              err = 0;

        dir = drv->opendir(ctx->sd, logical, &err);
        if (dir != NULL) {
            xrootd_sd_dirent_t de;
            ngx_int_t          drc;

            while ((drc = drv->readdir(dir, &de)) == NGX_OK) {
                char child[PATH_MAX];

                ngx_snprintf((u_char *) child, sizeof(child), "%s/%s%Z",
                             (logical[0] == '/' && logical[1] == '\0')
                                 ? "" : logical,
                             de.name);
                if (xrootd_vfs_driver_rmtree(ctx, drv, child) != NGX_OK) {
                    drv->closedir(dir);
                    return NGX_ERROR;
                }
            }
            drv->closedir(dir);
            if (drc == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
        return drv->unlink(ctx->sd, logical, 1);
    }

    return drv->unlink(ctx->sd, logical, 0);
}

/* Shared delete body for unlink/rmdir: write-gate, then xrootd_ns_delete with
 * the given recursive / require_empty_dir options; metered as OP_DELETE. */
static ngx_int_t
xrootd_vfs_delete(xrootd_vfs_ctx_t *ctx, unsigned recursive,
    unsigned require_empty_dir)
{
    xrootd_ns_delete_opts_t   opts;
    xrootd_ns_result_t        res;
    const char               *path;
    uint64_t                  start;
    int                       saved_errno;
    const xrootd_sd_driver_t *drv;

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

    /* Non-POSIX backend: delete through the driver namespace. A recursive delete
     * (WebDAV DELETE of a collection) walks the tree; a non-recursive delete is a
     * file unlink or empty-rmdir (require_directory selects is_dir). */
    drv = xrootd_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        const char *logical = xrootd_vfs_export_relative(ctx, path);
        ngx_int_t   rc;

        if (recursive) {
            rc = xrootd_vfs_driver_rmtree(ctx, drv, logical);
        } else if (drv->unlink != NULL) {
            rc = drv->unlink(ctx->sd, logical, require_empty_dir ? 1 : 0);
        } else {
            errno = ENOSYS;
            rc = NGX_ERROR;
        }
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DELETE, NULL, 0,
                                  rc, saved_errno, start);
        return rc;
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.recursive = recursive ? 1 : 0;
    opts.require_empty_dir = require_empty_dir ? 1 : 0;
    /* A non-recursive "empty dir" delete is rmdir, which must reject a regular
     * file (ENOTDIR) — kXR_rmdir parity. Recursive deletes (require_empty_dir=0)
     * remove a file directly, so require_directory stays off there. */
    opts.require_directory = require_empty_dir ? 1 : 0;

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
