/*
 * vfs_xattr.c — VFS extended-attribute family (get / set / remove / list).
 *
 * WHAT: Implements brix_vfs_getxattr/setxattr/removexattr/listxattr — the
 *       protocol-agnostic surface for the `user.`-namespace xattrs that S3
 *       object tagging, WebDAV dead properties, checksum sidecars, and the
 *       WebDAV lock database all store on export objects.
 *
 * WHY:  Before this unit those callers reached the confined xattr helpers
 *       (brix_*xattr_confined_canon) directly, so the xattr touches were
 *       confined but invisible to metrics/access-logging. Routing them here
 *       gives every xattr op one BRIX_METRIC_OP_XATTR metric + access-log line
 *       and the same guard-then-syscall-then-observe shape as the rest of the
 *       VFS, while still delegating the actual syscall (and impersonation broker
 *       routing) to the confined helpers.
 *
 * HOW:  Each entry point re-verifies confinement (brix_vfs_require_confined),
 *       calls the matching brix_*xattr_confined_canon with ctx->root_canon and
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
 * return the count unchanged (errno preserved on error). ENODATA is observed as
 * a clean zero-byte lookup, not an error: optional-attribute probes (S3
 * usermeta/tagging on GET, WebDAV dead props) routinely miss, and logging each
 * miss as a failed op:"xattr" line put error lines on every served GET. The
 * caller still sees -1/ENODATA unchanged. */
static ssize_t
brix_vfs_xattr_observe_count(const brix_vfs_ctx_t *ctx, const char *path,
    ssize_t n, ngx_msec_t start)
{
    int saved_errno = (n < 0) ? errno : 0;
    int absent_ok = (n >= 0) || saved_errno == ENODATA;

    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_XATTR, NULL,
                              (n > 0) ? (size_t) n : 0,
                              absent_ok ? NGX_OK : NGX_ERROR,
                              absent_ok ? 0 : saved_errno, start);
    if (n < 0) {
        errno = saved_errno;
    }
    return n;
}

/* Read attribute `name` on the resolved ctx path into buf[bufsz] (bufsz==0 asks
 * for the required size). Returns the byte count, or -1 with errno set
 * (ERANGE when the value does not fit). Metered as OP_XATTR. */
ssize_t
brix_vfs_getxattr(brix_vfs_ctx_t *ctx, const char *name,
    void *buf, size_t bufsz)
{
    const char *path = brix_vfs_ctx_path(ctx);
    uint64_t    start = brix_vfs_now_ns();
    ssize_t     n;

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_count(ctx, path, -1, start);
    }

    {
        const brix_sd_driver_t *drv = brix_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            brix_sd_ucred_t store;
            brix_sd_cred_t  cred;
            int             use_cred = 0, cred_err = 0;

            /* Zero before the gate: it fills only the active credential kind;
             * an unzeroed cred hands a garbage inactive pointer to the driver
             * cred slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
            ngx_memzero(&cred, sizeof(cred));

            if (brix_vfs_cred_gate_active(ctx)) {
                if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
                    != NGX_OK)
                {
                    errno = cred_err ? cred_err : EACCES;
                    return brix_vfs_xattr_observe_count(ctx, path, -1, start);
                }
            }
            /* Dispatch on the leaf so *_maybe_cred finds the leaf driver's
             * getxattr_cred slot (decorators have only plain relays). */
            n = (drv->getxattr != NULL)
                ? brix_sd_getxattr_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
                      brix_vfs_export_relative(ctx, path),
                      name, buf, bufsz, use_cred ? &cred : NULL)
                : (errno = ENOTSUP, (ssize_t) -1);
            brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
            return brix_vfs_xattr_observe_count(ctx, path, n, start);
        }
    }

    n = brix_getxattr_confined_canon(ctx->log, ctx->root_canon, path, name,
                                       buf, bufsz);
    return brix_vfs_xattr_observe_count(ctx, path, n, start);
}

/* List the attribute names on the resolved ctx path into buf[bufsz] (NUL-
 * separated; bufsz==0 asks for the required size). Returns the byte count, or
 * -1 with errno set. Metered as OP_XATTR. */
ssize_t
brix_vfs_listxattr(brix_vfs_ctx_t *ctx, void *buf, size_t bufsz)
{
    const char *path = brix_vfs_ctx_path(ctx);
    uint64_t    start = brix_vfs_now_ns();
    ssize_t     n;

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_count(ctx, path, -1, start);
    }

    {
        const brix_sd_driver_t *drv = brix_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            brix_sd_ucred_t store;
            brix_sd_cred_t  cred;
            int             use_cred = 0, cred_err = 0;

            /* Zero before the gate: it fills only the active credential kind;
             * an unzeroed cred hands a garbage inactive pointer to the driver
             * cred slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
            ngx_memzero(&cred, sizeof(cred));

            if (brix_vfs_cred_gate_active(ctx)) {
                if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
                    != NGX_OK)
                {
                    errno = cred_err ? cred_err : EACCES;
                    return brix_vfs_xattr_observe_count(ctx, path, -1, start);
                }
            }
            /* Dispatch on the leaf so *_maybe_cred finds the leaf driver's
             * listxattr_cred slot (decorators have only plain relays). */
            n = (drv->listxattr != NULL)
                ? brix_sd_listxattr_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
                      brix_vfs_export_relative(ctx, path),
                      buf, bufsz, use_cred ? &cred : NULL)
                : (errno = ENOTSUP, (ssize_t) -1);
            brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
            return brix_vfs_xattr_observe_count(ctx, path, n, start);
        }
    }

    n = brix_listxattr_confined_canon(ctx->log, ctx->root_canon, path,
                                        buf, bufsz);
    return brix_vfs_xattr_observe_count(ctx, path, n, start);
}

/* Observe a mutation (set/remove) result: translate an rc (0 ok, non-0 error
 * with errno already set) into an OP_XATTR metric + access-log line, reporting
 * `nbytes` on success and 0 on error, and return NGX_OK/NGX_ERROR. Shared by
 * the set/remove entry points so the observe tail is identical for both. */
static ngx_int_t
brix_vfs_xattr_observe_mut(const brix_vfs_ctx_t *ctx, const char *path,
    int rc, size_t nbytes, ngx_msec_t start)
{
    int saved_errno = (rc != 0) ? errno : 0;

    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_XATTR, NULL,
                              (rc == 0) ? nbytes : 0,
                              (rc != 0) ? NGX_ERROR : NGX_OK, saved_errno,
                              start);
    return (rc != 0) ? NGX_ERROR : NGX_OK;
}

/* Run the shared set/remove driver-path gates: the phase-71 write-capability
 * gate (CAP_XATTR_WRITE required) then the per-user credential gate. On success
 * returns NGX_OK with use_cred/cred populated for the dispatch; on failure
 * sets errno, emits the OP_XATTR error observation, and returns NGX_ERROR so the
 * caller can early-return without duplicating the observe tail. Byte-identical
 * to the inline gates the set/remove paths previously carried. */
static ngx_int_t
brix_vfs_xattr_write_gate(brix_vfs_ctx_t *ctx, const char *path,
    const brix_sd_driver_t *drv, brix_sd_ucred_t *store, brix_sd_cred_t *cred,
    int *use_cred, ngx_msec_t start)
{
    int cred_err = 0;

    /* Zero before the gate: it fills only the active credential kind; an
     * unzeroed cred hands a garbage inactive pointer to the driver cred slot
     * (bearer PASSTHROUGH would leave x509_proxy dangling). */
    ngx_memzero(cred, sizeof(*cred));

    /* phase-71: capability gate — a backend that can read xattrs but not write
     * them (CAP_XATTR without CAP_XATTR_WRITE) rejects set/remove uniformly,
     * regardless of whether the vtable slot is populated. */
    if (!(drv->caps & BRIX_SD_CAP_XATTR_WRITE)) {
        errno = ENOTSUP;
        (void) brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
        return NGX_ERROR;
    }

    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, store, cred, use_cred, &cred_err) != NGX_OK) {
            errno = cred_err ? cred_err : EACCES;
            (void) brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* Set attribute `name` to value[len] on the resolved ctx path. `flags` are the
 * raw setxattr(2) flags (XATTR_CREATE / XATTR_REPLACE / 0). Returns NGX_OK or
 * NGX_ERROR with errno set. Metered as OP_XATTR. Not allow_write-gated (the
 * protocol layer authorizes; lock writes occur on read-only requests). */
ngx_int_t
brix_vfs_setxattr(brix_vfs_ctx_t *ctx, const char *name,
    const void *value, size_t len, int flags)
{
    const char *path = brix_vfs_ctx_path(ctx);
    uint64_t    start = brix_vfs_now_ns();
    int         rc;

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
    }

    {
        const brix_sd_driver_t *drv = brix_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            brix_sd_ucred_t store;
            brix_sd_cred_t  cred;
            int             use_cred = 0;

            if (brix_vfs_xattr_write_gate(ctx, path, drv, &store, &cred,
                                            &use_cred, start) != NGX_OK)
            {
                return NGX_ERROR;
            }
            /* Dispatch on the leaf so *_maybe_cred finds the leaf driver's
             * setxattr_cred slot (decorators have only plain relays). */
            rc = (drv->setxattr != NULL
                  && brix_sd_setxattr_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
                         brix_vfs_export_relative(ctx, path),
                         name, value, len, flags,
                         use_cred ? &cred : NULL) == NGX_OK)
                 ? 0 : (errno = (drv->setxattr ? errno : ENOTSUP), -1);
            brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
            return brix_vfs_xattr_observe_mut(ctx, path, rc, len, start);
        }
    }

    rc = brix_setxattr_confined_canon(ctx->log, ctx->root_canon, path, name,
                                        value, len, flags);
    return brix_vfs_xattr_observe_mut(ctx, path, rc, len, start);
}

/* Remove attribute `name` from the resolved ctx path. Returns NGX_OK or
 * NGX_ERROR with errno set (ENODATA when the attribute is absent). Metered as
 * OP_XATTR. Not allow_write-gated (see brix_vfs_setxattr). */
ngx_int_t
brix_vfs_removexattr(brix_vfs_ctx_t *ctx, const char *name)
{
    const char *path = brix_vfs_ctx_path(ctx);
    uint64_t    start = brix_vfs_now_ns();
    int         rc;

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
    }

    {
        const brix_sd_driver_t *drv = brix_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            brix_sd_ucred_t store;
            brix_sd_cred_t  cred;
            int             use_cred = 0;

            if (brix_vfs_xattr_write_gate(ctx, path, drv, &store, &cred,
                                            &use_cred, start) != NGX_OK)
            {
                return NGX_ERROR;
            }
            /* Dispatch on the leaf so *_maybe_cred finds the leaf driver's
             * removexattr_cred slot (decorators have only plain relays). */
            rc = (drv->removexattr != NULL
                  && brix_sd_removexattr_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
                         brix_vfs_export_relative(ctx, path), name,
                         use_cred ? &cred : NULL) == NGX_OK)
                 ? 0 : (errno = (drv->removexattr ? errno : ENOTSUP), -1);
            brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
            return brix_vfs_xattr_observe_mut(ctx, path, rc, 0, start);
        }
    }

    rc = brix_removexattr_confined_canon(ctx->log, ctx->root_canon, path,
                                           name);
    return brix_vfs_xattr_observe_mut(ctx, path, rc, 0, start);
}

/* --- open-handle (fd) variants --------------------------------------------
 * The path variants above re-verify confinement against ctx->resolved before
 * each syscall. The fd variants below operate on an fd that the VFS already
 * opened confined (via brix_vfs_open / brix_vfs_adopt_fd, or a handle-table
 * fd that came from one), so the confinement guarantee travels with the
 * descriptor — there is no path to re-resolve. They exist so that fattr's
 * file-handle mode (and any other open-fd xattr caller) reaches the backend
 * through the VFS instead of calling f*xattr(2) directly.
 *
 * `ctx` is optional and used only for the OP_XATTR metric + access-log line; it
 * may be NULL (then the op is unobserved). It is NOT required to be confined —
 * passing the request's ctx simply attributes the metric to the right proto. */

ssize_t
brix_vfs_fgetxattr(const brix_vfs_ctx_t *ctx, int fd, const char *name,
    void *buf, size_t bufsz)
{
    uint64_t start = brix_vfs_now_ns();
    ssize_t  n = fgetxattr(fd, name, buf, bufsz);

    return brix_vfs_xattr_observe_count(ctx, NULL, n, start);
}

ssize_t
brix_vfs_flistxattr(const brix_vfs_ctx_t *ctx, int fd, void *buf,
    size_t bufsz)
{
    uint64_t start = brix_vfs_now_ns();
    ssize_t  n = flistxattr(fd, buf, bufsz);

    return brix_vfs_xattr_observe_count(ctx, NULL, n, start);
}

ngx_int_t
brix_vfs_fsetxattr(const brix_vfs_ctx_t *ctx, int fd, const char *name,
    const void *value, size_t len, int flags)
{
    uint64_t start = brix_vfs_now_ns();
    int      rc = fsetxattr(fd, name, value, len, flags);
    int      saved_errno = (rc != 0) ? errno : 0;

    brix_vfs_observe_ctx_op(ctx, NULL, BRIX_METRIC_OP_XATTR, NULL,
                              (rc == 0) ? len : 0,
                              (rc != 0) ? NGX_ERROR : NGX_OK, saved_errno,
                              start);
    return (rc != 0) ? NGX_ERROR : NGX_OK;
}

ngx_int_t
brix_vfs_fremovexattr(const brix_vfs_ctx_t *ctx, int fd, const char *name)
{
    uint64_t start = brix_vfs_now_ns();
    int      rc = fremovexattr(fd, name);
    int      saved_errno = (rc != 0) ? errno : 0;

    brix_vfs_observe_ctx_op(ctx, NULL, BRIX_METRIC_OP_XATTR, NULL, 0,
                              (rc != 0) ? NGX_ERROR : NGX_OK, saved_errno,
                              start);
    return (rc != 0) ? NGX_ERROR : NGX_OK;
}
