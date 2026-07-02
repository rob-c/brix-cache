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
#include "fs/path/path.h"   /* xrootd_chmod_confined_canon (impersonation-aware) */

/* Create the resolved ctx path as a directory (mode), creating parents when
 * `parents`. Write-gated and confined; metered as OP_MKDIR. */
ngx_int_t
xrootd_vfs_mkdir(xrootd_vfs_ctx_t *ctx, mode_t mode, unsigned parents)
{
    xrootd_ns_result_t        res;
    const char               *path;
    uint64_t                  start;
    int                       saved_errno;
    const xrootd_sd_driver_t *drv;

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

    /* Non-POSIX backend: create the directory entry in the driver's namespace.
     * (`parents` is advisory — an object/block backend's mkdir is a flat catalog
     * insert; the leaf appears regardless of parent rows.) */
    drv = xrootd_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        ngx_int_t rc = (drv->mkdir != NULL)
            ? drv->mkdir(ctx->sd, xrootd_vfs_export_relative(ctx, path), mode)
            : (errno = ENOSYS, NGX_ERROR);

        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_MKDIR, NULL, 0,
                                  rc, saved_errno, start);
        return rc;
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

/*
 * xrootd_vfs_chmod — change the resolved path's permission bits through the VFS
 * seam. Like xrootd_vfs_mkdir it delegates to the impersonation-aware confined
 * helper (xrootd_chmod_confined_canon) rather than a raw fchmodat, so under
 * impersonation the chmod is performed by the broker as the mapped user.
 */
ngx_int_t
xrootd_vfs_chmod(xrootd_vfs_ctx_t *ctx, mode_t mode)
{
    if (xrootd_vfs_require_write(ctx) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ctx->root_canon == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    /* A non-POSIX backend mutates mode through its setattr slot (e.g. pblock
     * updates the catalog row). A backend with no setattr slot has no mutable
     * metadata (block/object data-only namespaces) — accept as a no-op success so
     * MKCOL/PUT flows that chmod do not fail. */
    {
        const xrootd_sd_driver_t *drv = xrootd_vfs_ctx_driver(ctx);
        if (drv != NULL) {
            xrootd_sd_setattr_t attr;
            if (drv->setattr == NULL) {
                return NGX_OK;
            }
            ngx_memzero(&attr, sizeof(attr));
            attr.set_mode = 1;
            attr.mode = mode;
            return drv->setattr(ctx->sd,
                       xrootd_vfs_export_relative(ctx, xrootd_vfs_ctx_path(ctx)),
                       &attr) == NGX_OK ? NGX_OK : NGX_ERROR;
        }
    }
    if (xrootd_chmod_confined_canon(ctx->log, ctx->root_canon,
                                    xrootd_vfs_ctx_path(ctx), mode) != 0) {
        return NGX_ERROR;   /* errno set by the helper */
    }
    return NGX_OK;
}

/*
 * xrootd_vfs_setattr — apply kXR_setattr (times and/or owner) to the resolved
 * path through the VFS seam. A non-POSIX backend routes to its setattr slot
 * (no-op success if it has none); the default POSIX path uses the
 * impersonation-aware confined utimensat/fchownat helper so under impersonation
 * the change is performed by the broker as the mapped user. The unified slot also
 * carries mode, so a backend satisfies chmod and setattr through one entry point —
 * kXR_setattr itself never sets mode (that is kXR_chmod's job).
 */
ngx_int_t
xrootd_vfs_setattr(xrootd_vfs_ctx_t *ctx, const xrootd_sd_setattr_t *attr)
{
    if (xrootd_vfs_require_write(ctx) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ctx->root_canon == NULL || attr == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    {
        const xrootd_sd_driver_t *drv = xrootd_vfs_ctx_driver(ctx);
        if (drv != NULL) {
            if (drv->setattr == NULL) {
                return NGX_OK;   /* no mutable metadata — no-op success */
            }
            return drv->setattr(ctx->sd,
                       xrootd_vfs_export_relative(ctx, xrootd_vfs_ctx_path(ctx)),
                       attr) == NGX_OK ? NGX_OK : NGX_ERROR;
        }
    }

    {
        struct timespec times[2];
        times[0] = attr->atime;
        times[1] = attr->mtime;
        if (xrootd_setattr_confined_canon(ctx->log, ctx->root_canon,
                xrootd_vfs_ctx_path(ctx), attr->set_times, times,
                attr->set_owner, attr->uid, attr->gid) != 0) {
            return NGX_ERROR;
        }
        if (attr->set_mode
            && xrootd_chmod_confined_canon(ctx->log, ctx->root_canon,
                                           xrootd_vfs_ctx_path(ctx), attr->mode) != 0) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}
