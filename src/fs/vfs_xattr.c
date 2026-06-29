/*
 * vfs_xattr.c — VFS extended-attribute family (get / set / remove / list).
 *
 * WHAT: Implements xrootd_vfs_getxattr/setxattr/removexattr/listxattr — the
 *       protocol-agnostic surface for the `user.`-namespace xattrs that S3
 *       object tagging, WebDAV dead properties, checksum sidecars, and the
 *       WebDAV lock database all store on export objects.
 *
 * WHY:  Before this unit those callers reached the confined xattr helpers
 *       (xrootd_*xattr_confined_canon) directly, so the xattr touches were
 *       confined but invisible to metrics/access-logging. Routing them here
 *       gives every xattr op one XROOTD_METRIC_OP_XATTR metric + access-log line
 *       and the same guard-then-syscall-then-observe shape as the rest of the
 *       VFS, while still delegating the actual syscall (and impersonation broker
 *       routing) to the confined helpers.
 *
 * HOW:  Each entry point re-verifies confinement (xrootd_vfs_require_confined),
 *       calls the matching xrootd_*xattr_confined_canon with ctx->root_canon and
 *       the resolved path, then observes the result as OP_XATTR. set/remove are
 *       mutations but are intentionally NOT allow_write-gated: the lock-database
 *       writes happen on otherwise read-only requests and the protocol layer has
 *       already authorized the principal — matching the prior direct-call
 *       behaviour exactly (no new EACCES surface). get/list propagate the helper
 *       byte count (or ERANGE) unchanged.
 */
#include "vfs_internal.h"

#include <sys/xattr.h>

/* Shared observe tail for the value-returning ops (get/list): translate a
 * helper return (>=0 ok, -1 errno) into an OP_XATTR metric + access-log line and
 * return the count unchanged (errno preserved on error). */
static ssize_t
xrootd_vfs_xattr_observe_count(const xrootd_vfs_ctx_t *ctx, const char *path,
    ssize_t n, ngx_msec_t start)
{
    int saved_errno = (n < 0) ? errno : 0;

    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_XATTR, NULL,
                              (n > 0) ? (size_t) n : 0,
                              (n < 0) ? NGX_ERROR : NGX_OK, saved_errno, start);
    return n;
}

/* Read attribute `name` on the resolved ctx path into buf[bufsz] (bufsz==0 asks
 * for the required size). Returns the byte count, or -1 with errno set
 * (ERANGE when the value does not fit). Metered as OP_XATTR. */
ssize_t
xrootd_vfs_getxattr(xrootd_vfs_ctx_t *ctx, const char *name,
    void *buf, size_t bufsz)
{
    const char *path = xrootd_vfs_ctx_path(ctx);
    uint64_t    start = xrootd_vfs_now_ns();
    ssize_t     n;

    if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
        return xrootd_vfs_xattr_observe_count(ctx, path, -1, start);
    }

    {
        const xrootd_sd_driver_t *drv = xrootd_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            n = (drv->getxattr != NULL)
                ? drv->getxattr(ctx->sd, xrootd_vfs_export_relative(ctx, path),
                                name, buf, bufsz)
                : (errno = ENOTSUP, (ssize_t) -1);
            return xrootd_vfs_xattr_observe_count(ctx, path, n, start);
        }
    }

    n = xrootd_getxattr_confined_canon(ctx->log, ctx->root_canon, path, name,
                                       buf, bufsz);
    return xrootd_vfs_xattr_observe_count(ctx, path, n, start);
}

/* List the attribute names on the resolved ctx path into buf[bufsz] (NUL-
 * separated; bufsz==0 asks for the required size). Returns the byte count, or
 * -1 with errno set. Metered as OP_XATTR. */
ssize_t
xrootd_vfs_listxattr(xrootd_vfs_ctx_t *ctx, void *buf, size_t bufsz)
{
    const char *path = xrootd_vfs_ctx_path(ctx);
    uint64_t    start = xrootd_vfs_now_ns();
    ssize_t     n;

    if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
        return xrootd_vfs_xattr_observe_count(ctx, path, -1, start);
    }

    {
        const xrootd_sd_driver_t *drv = xrootd_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            n = (drv->listxattr != NULL)
                ? drv->listxattr(ctx->sd, xrootd_vfs_export_relative(ctx, path),
                                 buf, bufsz)
                : (errno = ENOTSUP, (ssize_t) -1);
            return xrootd_vfs_xattr_observe_count(ctx, path, n, start);
        }
    }

    n = xrootd_listxattr_confined_canon(ctx->log, ctx->root_canon, path,
                                        buf, bufsz);
    return xrootd_vfs_xattr_observe_count(ctx, path, n, start);
}

/* Set attribute `name` to value[len] on the resolved ctx path. `flags` are the
 * raw setxattr(2) flags (XATTR_CREATE / XATTR_REPLACE / 0). Returns NGX_OK or
 * NGX_ERROR with errno set. Metered as OP_XATTR. Not allow_write-gated (the
 * protocol layer authorizes; lock writes occur on read-only requests). */
ngx_int_t
xrootd_vfs_setxattr(xrootd_vfs_ctx_t *ctx, const char *name,
    const void *value, size_t len, int flags)
{
    const char *path = xrootd_vfs_ctx_path(ctx);
    uint64_t    start = xrootd_vfs_now_ns();
    int         rc;
    int         saved_errno;

    if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_XATTR, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    {
        const xrootd_sd_driver_t *drv = xrootd_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            rc = (drv->setxattr != NULL
                  && drv->setxattr(ctx->sd, xrootd_vfs_export_relative(ctx, path),
                                   name, value, len, flags) == NGX_OK)
                 ? 0 : (errno = (drv->setxattr ? errno : ENOTSUP), -1);
            saved_errno = (rc != 0) ? errno : 0;
            xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_XATTR, NULL,
                                      (rc == 0) ? len : 0,
                                      (rc != 0) ? NGX_ERROR : NGX_OK,
                                      saved_errno, start);
            return (rc != 0) ? NGX_ERROR : NGX_OK;
        }
    }

    rc = xrootd_setxattr_confined_canon(ctx->log, ctx->root_canon, path, name,
                                        value, len, flags);
    saved_errno = (rc != 0) ? errno : 0;
    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_XATTR, NULL,
                              (rc == 0) ? len : 0,
                              (rc != 0) ? NGX_ERROR : NGX_OK, saved_errno,
                              start);
    return (rc != 0) ? NGX_ERROR : NGX_OK;
}

/* Remove attribute `name` from the resolved ctx path. Returns NGX_OK or
 * NGX_ERROR with errno set (ENODATA when the attribute is absent). Metered as
 * OP_XATTR. Not allow_write-gated (see xrootd_vfs_setxattr). */
ngx_int_t
xrootd_vfs_removexattr(xrootd_vfs_ctx_t *ctx, const char *name)
{
    const char *path = xrootd_vfs_ctx_path(ctx);
    uint64_t    start = xrootd_vfs_now_ns();
    int         rc;
    int         saved_errno;

    if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_XATTR, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    {
        const xrootd_sd_driver_t *drv = xrootd_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            rc = (drv->removexattr != NULL
                  && drv->removexattr(ctx->sd,
                         xrootd_vfs_export_relative(ctx, path), name) == NGX_OK)
                 ? 0 : (errno = (drv->removexattr ? errno : ENOTSUP), -1);
            saved_errno = (rc != 0) ? errno : 0;
            xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_XATTR, NULL, 0,
                                      (rc != 0) ? NGX_ERROR : NGX_OK,
                                      saved_errno, start);
            return (rc != 0) ? NGX_ERROR : NGX_OK;
        }
    }

    rc = xrootd_removexattr_confined_canon(ctx->log, ctx->root_canon, path,
                                           name);
    saved_errno = (rc != 0) ? errno : 0;
    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_XATTR, NULL, 0,
                              (rc != 0) ? NGX_ERROR : NGX_OK, saved_errno,
                              start);
    return (rc != 0) ? NGX_ERROR : NGX_OK;
}

/* --- open-handle (fd) variants --------------------------------------------
 * The path variants above re-verify confinement against ctx->resolved before
 * each syscall. The fd variants below operate on an fd that the VFS already
 * opened confined (via xrootd_vfs_open / xrootd_vfs_adopt_fd, or a handle-table
 * fd that came from one), so the confinement guarantee travels with the
 * descriptor — there is no path to re-resolve. They exist so that fattr's
 * file-handle mode (and any other open-fd xattr caller) reaches the backend
 * through the VFS instead of calling f*xattr(2) directly.
 *
 * `ctx` is optional and used only for the OP_XATTR metric + access-log line; it
 * may be NULL (then the op is unobserved). It is NOT required to be confined —
 * passing the request's ctx simply attributes the metric to the right proto. */

ssize_t
xrootd_vfs_fgetxattr(const xrootd_vfs_ctx_t *ctx, int fd, const char *name,
    void *buf, size_t bufsz)
{
    uint64_t start = xrootd_vfs_now_ns();
    ssize_t  n = fgetxattr(fd, name, buf, bufsz);

    return xrootd_vfs_xattr_observe_count(ctx, NULL, n, start);
}

ssize_t
xrootd_vfs_flistxattr(const xrootd_vfs_ctx_t *ctx, int fd, void *buf,
    size_t bufsz)
{
    uint64_t start = xrootd_vfs_now_ns();
    ssize_t  n = flistxattr(fd, buf, bufsz);

    return xrootd_vfs_xattr_observe_count(ctx, NULL, n, start);
}

ngx_int_t
xrootd_vfs_fsetxattr(const xrootd_vfs_ctx_t *ctx, int fd, const char *name,
    const void *value, size_t len, int flags)
{
    uint64_t start = xrootd_vfs_now_ns();
    int      rc = fsetxattr(fd, name, value, len, flags);
    int      saved_errno = (rc != 0) ? errno : 0;

    xrootd_vfs_observe_ctx_op(ctx, NULL, XROOTD_METRIC_OP_XATTR, NULL,
                              (rc == 0) ? len : 0,
                              (rc != 0) ? NGX_ERROR : NGX_OK, saved_errno,
                              start);
    return (rc != 0) ? NGX_ERROR : NGX_OK;
}

ngx_int_t
xrootd_vfs_fremovexattr(const xrootd_vfs_ctx_t *ctx, int fd, const char *name)
{
    uint64_t start = xrootd_vfs_now_ns();
    int      rc = fremovexattr(fd, name);
    int      saved_errno = (rc != 0) ? errno : 0;

    xrootd_vfs_observe_ctx_op(ctx, NULL, XROOTD_METRIC_OP_XATTR, NULL, 0,
                              (rc != 0) ? NGX_ERROR : NGX_OK, saved_errno,
                              start);
    return (rc != 0) ? NGX_ERROR : NGX_OK;
}
