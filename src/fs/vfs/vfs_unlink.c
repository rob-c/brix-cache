/*
 * vfs_unlink.c — VFS delete family (unlink / rmdir).
 *
 * WHAT: Implements brix_vfs_unlink() (remove a regular file) and
 *       brix_vfs_rmdir() (remove a directory, recursively or only when empty),
 *       both thin wrappers over the shared brix_vfs_delete() helper.
 *
 * WHY:  Deletes are write-gated and must be applied through the namespace layer
 *       (../compat/namespace_ops) so confinement and the recursive / require-
 *       empty semantics match the rest of the namespace mutators, with one
 *       metric/access-log emission per call.
 *
 * HOW:  brix_vfs_delete() enforces brix_vfs_require_write() and a non-NULL
 *       root_canon, builds an brix_ns_delete_opts_t (recursive,
 *       require_empty_dir), and calls brix_ns_delete(); the namespace status
 *       is mapped back to errno (sys_errno or EIO) and observed as
 *       BRIX_METRIC_OP_DELETE. rmdir requests require_empty_dir only when not
 *       recursive.
 */
#include "vfs_internal.h"

/* brix_vfs_driver_rmtree — depth-first delete of `logical` through the storage
 * driver: a file is unlinked directly; a directory has its children removed
 * (opendir/readdir recursion) before the now-empty directory itself.
 *
 * WHAT: Recursive WebDAV DELETE of a collection on a non-POSIX backend:
 *       dispatches stat/opendir/readdir/unlink through the LEAF driver so that
 *       per-user credentials (stat_cred / unlink_cred / opendir_cred) are
 *       presented at every level of the tree, not just the top-level call.
 *
 * WHY:  Calling drv->stat(ctx->sd, …) / drv->unlink(ctx->sd, …) bypasses the
 *       cred entirely because ctx->sd may be a decorator without *_cred slots.
 *       Dispatching through brix_sd_*_maybe_cred on the leaf ensures that a
 *       user credential, when present (use_cred=1), is threaded through the
 *       entire recursive walk — not just the outermost call.
 *
 * HOW:  Accepts the pre-resolved leaf `leaf` and pre-computed `cred` pointer
 *       (NULL when use_cred=0) from the caller, uses brix_sd_*_maybe_cred on
 *       `leaf` for every driver call, and recurses with the same arguments. */
static ngx_int_t
brix_vfs_driver_rmtree(brix_sd_instance_t *leaf, const brix_sd_driver_t *drv,
    const char *logical, const brix_sd_cred_t *cred)
{
    brix_sd_stat_t st;

    if (drv->stat == NULL || drv->unlink == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    if (brix_sd_stat_maybe_cred(leaf, logical, &st, cred) != NGX_OK) {
        return NGX_ERROR;            /* ENOENT etc. — errno set by the driver */
    }

    if (st.is_dir && drv->opendir != NULL) {
        brix_sd_dir_t *dir;
        int              err = 0;

        dir = brix_sd_opendir_maybe_cred(leaf, logical, &err, cred);
        if (dir != NULL) {
            brix_sd_dirent_t de;
            ngx_int_t          drc;

            while ((drc = drv->readdir(dir, &de)) == NGX_OK) {
                char child[PATH_MAX];

                ngx_snprintf((u_char *) child, sizeof(child), "%s/%s%Z",
                             (logical[0] == '/' && logical[1] == '\0')
                                 ? "" : logical,
                             de.name);
                if (brix_vfs_driver_rmtree(leaf, drv, child, cred) != NGX_OK) {
                    drv->closedir(dir);
                    return NGX_ERROR;
                }
            }
            drv->closedir(dir);
            if (drc == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
        return brix_sd_unlink_maybe_cred(leaf, logical, 1, cred);
    }

    return brix_sd_unlink_maybe_cred(leaf, logical, 0, cred);
}

/* Shared delete body for unlink/rmdir: write-gate, then brix_ns_delete with
 * the given recursive / require_empty_dir options; metered as OP_DELETE. */
static ngx_int_t
brix_vfs_delete(brix_vfs_ctx_t *ctx, unsigned recursive,
    unsigned require_empty_dir)
{
    brix_ns_delete_opts_t   opts;
    brix_ns_result_t        res;
    const char               *path;
    uint64_t                  start;
    int                       saved_errno;
    const brix_sd_driver_t *drv;

    start = brix_vfs_now_ns();
    path = brix_vfs_ctx_path(ctx);

    if (brix_vfs_require_write(ctx) != NGX_OK) {
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DELETE, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (ctx->root_canon == NULL) {
        errno = EINVAL;
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DELETE, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    /* Non-POSIX backend: delete through the driver namespace. A recursive delete
     * (WebDAV DELETE of a collection) walks the tree; a non-recursive delete is a
     * file unlink or empty-rmdir (require_directory selects is_dir).
     * Dispatch on the leaf instance so *_maybe_cred forwarders find the leaf
     * driver's *_cred slots (decorators have only plain relays). */
    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        const char         *logical = brix_vfs_export_relative(ctx, path);
        brix_sd_instance_t *leaf    = brix_vfs_ns_leaf(ctx->sd);
        brix_sd_ucred_t     store;
        brix_sd_cred_t      cred;
        ngx_int_t           rc;
        int                 use_cred = 0, cred_err = 0;

        /* Zero before the gate: it fills only the active credential kind; an
         * unzeroed cred hands a garbage inactive pointer to the driver's
         * cred slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
        ngx_memzero(&cred, sizeof(cred));

        if (brix_vfs_cred_gate_active(ctx)) {
            if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
                != NGX_OK)
            {
                saved_errno = cred_err ? cred_err : EACCES;
                errno = saved_errno;
                brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DELETE,
                                          NULL, 0, NGX_ERROR, saved_errno,
                                          start);
                return NGX_ERROR;
            }
        }

        if (recursive) {
            rc = brix_vfs_driver_rmtree(leaf, drv, logical,
                                        use_cred ? &cred : NULL);
        } else if (drv->unlink != NULL) {
            rc = brix_sd_unlink_maybe_cred(leaf, logical,
                     require_empty_dir ? 1 : 0, use_cred ? &cred : NULL);
        } else {
            errno = ENOSYS;
            rc = NGX_ERROR;
        }
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DELETE, NULL, 0,
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

    res = brix_ns_delete(ctx->log, ctx->root_canon,
                           brix_vfs_ctx_path(ctx), &opts);
    if (res.status == BRIX_NS_OK) {
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DELETE, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    errno = res.sys_errno != 0 ? res.sys_errno
                               : brix_vfs_ns_status_errno(res.status);
    saved_errno = errno;
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DELETE, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}

/* Remove a single regular file (non-recursive, no empty-dir requirement). */
ngx_int_t
brix_vfs_unlink(brix_vfs_ctx_t *ctx)
{
    return brix_vfs_delete(ctx, 0, 0);
}

/* Remove a directory: recursively when `recursive`, otherwise only if empty. */
ngx_int_t
brix_vfs_rmdir(brix_vfs_ctx_t *ctx, unsigned recursive)
{
    return brix_vfs_delete(ctx, recursive, recursive ? 0 : 1);
}
