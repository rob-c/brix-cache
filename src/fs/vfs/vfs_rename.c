/*
 * vfs_rename.c — VFS rename / move.
 *
 * WHAT: Implements brix_vfs_rename(), which moves the resolved ctx (source)
 *       path to a caller-supplied, already-resolved destination
 *       brix_path_result_t.
 *
 * WHY:  kXR_mv and WebDAV MOVE need a single write-gated, confined rename whose
 *       destination is verified to be inside the export root before the syscall,
 *       with one metric/access-log line — not an ad-hoc rename(2) per protocol.
 *
 * HOW:  Enforces brix_vfs_require_write(), then demands a non-NULL root_canon
 *       and a destination that is itself is_confined with a non-empty resolved
 *       path. It delegates the actual move to brix_ns_rename() (namespace
 *       layer), maps the returned status back to errno (sys_errno or EIO), and
 *       observes the operation as BRIX_METRIC_OP_RENAME on every path.
 */
#include "vfs_internal.h"

/* Thread-safe confined rename (no pool alloc, no metric) — relocates the
 * namespace rename into the VFS layer for off-thread / pool-less callers (kXR_mv,
 * WebDAV MOVE collection offload). Maps the namespace status to errno + an
 * optional was_dir flag; see vfs.h. */
ngx_int_t
brix_vfs_rename_path(brix_sd_instance_t *sd, ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    unsigned overwrite, int *was_dir_out)
{
    brix_ns_result_t res;

    /* Non-POSIX backend: rename in the driver namespace (export-relative keys).
     * was_dir is derived from a post-rename stat of the destination. */
    if (sd != NULL && sd->driver != brix_sd_default_driver()
        && sd->driver->rename != NULL)
    {
        const char *s = brix_vfs_export_relative_root(src, root_canon);
        const char *d = brix_vfs_export_relative_root(dst, root_canon);
        ngx_int_t   rc = sd->driver->rename(sd, s, d, overwrite ? 0 : 1);

        if (was_dir_out != NULL) {
            brix_sd_stat_t st;

            *was_dir_out = (rc == NGX_OK && sd->driver->stat != NULL
                            && sd->driver->stat(sd, d, &st) == NGX_OK)
                               ? st.is_dir : 0;
        }
        return rc;
    }

    res = brix_ns_rename(log, root_canon, src, dst, overwrite ? 1 : 0);
    if (was_dir_out != NULL) {
        *was_dir_out = res.was_dir;
    }
    if (res.status == BRIX_NS_OK) {
        return NGX_OK;
    }
    errno = res.sys_errno != 0 ? res.sys_errno
                               : brix_vfs_ns_status_errno(res.status);
    return NGX_ERROR;
}

/* Move the resolved ctx source path to the confined destination `dst`.
 * Write-gated; both endpoints must be confined. Metered as OP_RENAME.
 * `overwrite_dirs` lets the rename replace an existing directory destination
 * (its tree is removed first — WebDAV MOVE Overwrite:T); 0 keeps kXR_mv
 * semantics where an existing dir dest fails with EEXIST. */
ngx_int_t
brix_vfs_rename(brix_vfs_ctx_t *ctx, const brix_path_result_t *dst,
    unsigned overwrite_dirs)
{
    brix_ns_result_t        res;
    const char               *path;
    uint64_t                  start;
    int                       saved_errno;
    const brix_sd_driver_t *drv;

    start = brix_vfs_now_ns();
    path = brix_vfs_ctx_path(ctx);

    if (brix_vfs_require_write(ctx) != NGX_OK) {
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (ctx->root_canon == NULL || dst == NULL || !dst->is_confined
        || dst->resolved.data == NULL)
    {
        errno = EINVAL;
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    /* Non-POSIX backend: rename within the driver namespace (both endpoints are
     * keyed export-relative; the move carries content via the catalog).
     * Dispatch on the leaf instance so brix_sd_rename_maybe_cred finds the
     * leaf driver's rename_cred slot (decorators have only plain relays). */
    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        brix_sd_instance_t *leaf = brix_vfs_ns_leaf(ctx->sd);
        brix_sd_ucred_t     store;
        brix_sd_cred_t      cred;
        ngx_int_t           rc;
        int                 use_cred = 0, cred_err = 0;

        /* Zero before the gate: it fills only the active credential kind; an
         * unzeroed cred hands a garbage inactive pointer to the driver's
         * cred slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
        ngx_memzero(&cred, sizeof(cred));

        /* phase-71: catalog-mutation capability gate — a read-only catalog
         * (CAP_DIRS without CAP_DIRS_WRITE) rejects rename uniformly. */
        if (!(drv->caps & BRIX_SD_CAP_DIRS_WRITE)) {
            saved_errno = EPERM;
            errno = saved_errno;
            brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                      NGX_ERROR, saved_errno, start);
            return NGX_ERROR;
        }
        if (brix_vfs_cred_gate_active(ctx)) {
            if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
                != NGX_OK)
            {
                saved_errno = cred_err ? cred_err : EACCES;
                errno = saved_errno;
                brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME,
                                          NULL, 0, NGX_ERROR, saved_errno,
                                          start);
                return NGX_ERROR;
            }
        }

        rc = (drv->rename != NULL)
            ? brix_sd_rename_maybe_cred(leaf,
                  brix_vfs_export_relative(ctx, path),
                  brix_vfs_export_relative(ctx,
                      (const char *) dst->resolved.data),
                  0, use_cred ? &cred : NULL)
            : (errno = ENOTSUP, NGX_ERROR);

        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  rc, saved_errno, start);
        return rc;
    }

    res = brix_ns_rename(ctx->log, ctx->root_canon,
                           brix_vfs_ctx_path(ctx),
                           (const char *) dst->resolved.data,
                           overwrite_dirs ? 1 : 0);
    if (res.status == BRIX_NS_OK) {
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    /* A pre-checked refusal (e.g. destination is an existing directory →
     * BRIX_NS_EXISTS) carries no syscall errno; map the status instead of
     * collapsing it to EIO so mv/MOVE report the true category. */
    errno = res.sys_errno != 0 ? res.sys_errno
                               : brix_vfs_ns_status_errno(res.status);
    saved_errno = errno;
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}
