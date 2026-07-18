/*
 * vfs_mkdir.c — VFS directory creation.
 *
 * WHAT: Implements brix_vfs_mkdir(), which creates the resolved ctx path as a
 *       directory with the given mode, optionally creating missing parent
 *       components (`parents`).
 *
 * WHY:  kXR_mkdir and WebDAV MKCOL need one write-gated, confined mkdir with the
 *       same parent-creation semantics and a single metric/access-log emission
 *       as the other namespace mutators.
 *
 * HOW:  Enforces brix_vfs_require_write() and a non-NULL root_canon, then
 *       delegates to brix_ns_mkdir() (namespace layer) passing mode and the
 *       parents flag. The namespace status is mapped back to errno (sys_errno or
 *       EIO) and observed as BRIX_METRIC_OP_MKDIR on every path.
 */
#include "vfs_internal.h"
#include "fs/path/path.h"   /* brix_chmod_confined_canon (impersonation-aware) */

/* vfs_backend_mkpath_leaf — leaf-aware recursive mkdir for non-POSIX backends.
 *
 * WHAT: Creates each prefix of `logical` in turn through brix_sd_mkdir_maybe_cred
 *       on `leaf`, tolerating EEXIST at each level.  Like brix_vfs_backend_mkpath
 *       but dispatches on the leaf driver and threads a per-user credential so
 *       the remote origin receives the user's identity on every mkdir call.
 *
 * WHY:  brix_vfs_backend_mkpath resolves the backend via brix_vfs_backend_resolve
 *       (which returns the TOP instance) and calls sd->driver->mkdir directly,
 *       bypassing both the leaf unwrap and the credential.  When `parents` is set
 *       and use_cred is non-zero, we must present the user credential to the leaf
 *       for every intermediate mkdir — not just the final one.  A local helper
 *       that already has `leaf` and `cred` avoids touching the shared
 *       brix_vfs_backend_mkpath signature (used by callers without cred).
 *
 * HOW:  Walk `logical` component-by-component, accumulating the path prefix in
 *       `acc`, calling brix_sd_mkdir_maybe_cred(leaf, acc, mode, cred) for each
 *       non-root prefix (EEXIST-tolerant).  Returns 0 on success, -1 with errno
 *       set on a real failure.  NGX_DECLINED (positive) when the leaf has no
 *       mkdir slot (caller falls back to brix_vfs_backend_mkpath). */
static int
vfs_backend_mkpath_leaf(brix_sd_instance_t *leaf, const char *logical,
    mode_t mode, const brix_sd_cred_t *cred)
{
    char   acc[PATH_MAX];
    size_t i = 0, j = 0;

    if (leaf == NULL || leaf->driver->mkdir == NULL) {
        /* Not a real failure — the caller falls back to
         * brix_vfs_backend_mkpath — but set errno for clarity to any caller
         * that inspects it before checking the NGX_DECLINED return. */
        errno = ENOTSUP;
        return NGX_DECLINED;
    }

    while (logical[i] != '\0') {
        if (logical[i] != '/') {
            i++;
            continue;
        }
        if (j + 1 >= sizeof(acc)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        acc[j++] = '/';
        i++;
        while (logical[i] != '\0' && logical[i] != '/') {
            if (j + 1 >= sizeof(acc)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            acc[j++] = logical[i++];
        }
        acc[j] = '\0';
        if (j > 1
            && brix_sd_mkdir_maybe_cred(leaf, acc, mode, cred) != NGX_OK
            && errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

/* vfs_mkdir_req_t — the resolved, gated mkdir request threaded to the backend
 * dispatch. WHAT: bundles ctx, the target `path`, mode, the parents flag, and
 * the OP_MKDIR observation start timestamp. WHY: keeps the backend helpers'
 * parameter lists small (one request pointer instead of five scalars) without
 * introducing globals — all state is passed explicitly. HOW: filled once in
 * brix_vfs_mkdir and passed by const pointer down the backend path. */
typedef struct {
    brix_vfs_ctx_t *ctx;
    const char     *path;
    mode_t          mode;
    unsigned        parents;
    uint64_t        start;
} vfs_mkdir_req_t;

/* vfs_backend_mkdir_dispatch — run the resolved mkdir against a non-POSIX
 * driver, honouring `parents` and a per-user credential.
 *
 * WHAT: Given the already-gated `leaf` instance, credential, and use_cred flag,
 *       creates the request's export-relative path as a directory. For the
 *       parents case it walks the whole prefix chain (leaf-aware+cred when
 *       use_cred, else brix_vfs_backend_mkpath); otherwise a single
 *       brix_sd_mkdir_maybe_cred. Returns NGX_OK / NGX_ERROR with errno set.
 *
 * WHY:  Isolates the three-way mkdir dispatch (no-slot / parents / single) from
 *       brix_vfs_mkdir so the caller stays under the complexity cap. The gate
 *       (caps, credential) is resolved by the caller and passed in explicitly —
 *       this helper is pure dispatch with side effects at the driver edge.
 *
 * HOW:  Rejects a NULL mkdir slot with ENOTSUP. For `parents` picks the
 *       leaf-aware cred-threaded mkpath when use_cred, else the root-canon
 *       mkpath, mapping a 0/-1 return to NGX_OK/NGX_ERROR. The non-parents case
 *       returns brix_sd_mkdir_maybe_cred directly. */
static ngx_int_t
vfs_backend_mkdir_dispatch(const vfs_mkdir_req_t *req,
    const brix_sd_driver_t *drv, brix_sd_instance_t *leaf,
    int use_cred, const brix_sd_cred_t *cred)
{
    brix_vfs_ctx_t *ctx = req->ctx;
    const char     *logical = brix_vfs_export_relative(ctx, req->path);

    if (drv->mkdir == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (req->parents) {
        int mkrc;

        if (use_cred) {
            /* Leaf-aware, cred-threaded mkpath for the per-user case. */
            mkrc = vfs_backend_mkpath_leaf(leaf, logical, req->mode, cred);
        } else {
            mkrc = brix_vfs_backend_mkpath(ctx->root_canon, logical, req->mode,
                                           ctx->log);
        }
        return (mkrc == 0) ? NGX_OK : NGX_ERROR;
    }
    return brix_sd_mkdir_maybe_cred(leaf, logical, req->mode,
                                    use_cred ? cred : NULL);
}

/* vfs_mkdir_backend — mkdir path for a non-POSIX driver (caps gate + cred gate
 * + dispatch + observe).
 *
 * WHAT: Enforces the catalog-mutation capability, resolves any per-user
 *       credential, dispatches the mkdir via vfs_backend_mkdir_dispatch, and
 *       emits the single OP_MKDIR observation. Returns the mkdir result.
 *
 * WHY:  The non-POSIX backend case carries most of brix_vfs_mkdir's branching;
 *       hoisting it here keeps brix_vfs_mkdir a thin router (write gate,
 *       root_canon, backend-vs-POSIX) under the complexity cap without changing
 *       any ordering, error path, or observation.
 *
 * HOW:  Rejects a driver lacking BRIX_SD_CAP_DIRS_WRITE with EPERM. When the
 *       credential gate is active, resolves the cred (EACCES/cred_err on
 *       failure). Both early exits observe before returning, exactly as the
 *       success path does. The credential is zeroed before the gate so an
 *       inactive-kind pointer is never handed to the driver. */
static ngx_int_t
vfs_mkdir_backend(const vfs_mkdir_req_t *req, const brix_sd_driver_t *drv)
{
    brix_vfs_ctx_t     *ctx = req->ctx;
    const char         *path = req->path;
    uint64_t            start = req->start;
    brix_sd_instance_t *leaf = brix_vfs_ns_leaf(ctx->sd);
    brix_sd_ucred_t     store;
    brix_sd_cred_t      cred;
    ngx_int_t           rc;
    int                 saved_errno;
    int                 use_cred = 0, cred_err = 0;

    /* Zero before the gate: it fills only the active credential kind; an
     * unzeroed cred hands a garbage inactive pointer to the driver's
     * cred slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
    ngx_memzero(&store, sizeof(store));
    ngx_memzero(&cred, sizeof(cred));

    /* phase-71: catalog-mutation capability gate. A backend that can list
     * directories (CAP_DIRS) but not mutate the catalog (no CAP_DIRS_WRITE)
     * rejects mkdir uniformly rather than relying on a NULL vtable slot. */
    if (!(drv->caps & BRIX_SD_CAP_DIRS_WRITE)) {
        saved_errno = EPERM;
        errno = saved_errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_MKDIR, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }
    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
            != NGX_OK)
        {
            saved_errno = cred_err ? cred_err : EACCES;
            errno = saved_errno;
            brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_MKDIR,
                                      NULL, 0, NGX_ERROR, saved_errno,
                                      start);
            return NGX_ERROR;
        }
    }

    rc = vfs_backend_mkdir_dispatch(req, drv, leaf, use_cred, &cred);
    brix_sd_ucred_wipe(&store);   /* secret consumed by mkdir; erase (A-4/T4) */

    saved_errno = errno;
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_MKDIR, NULL, 0,
                              rc, saved_errno, start);
    return rc;
}

/* Create the resolved ctx path as a directory (mode), creating parents when
 * `parents`. Write-gated and confined; metered as OP_MKDIR. */
ngx_int_t
brix_vfs_mkdir(brix_vfs_ctx_t *ctx, mode_t mode, unsigned parents)
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
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_MKDIR, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (ctx->root_canon == NULL) {
        errno = EINVAL;
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_MKDIR, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    /* Non-POSIX backend: create the directory entry in the driver's namespace.
     * The catalog enforces POSIX parent existence (a lone mkdir with missing
     * ancestors is ENOENT), so `parents` walks the whole chain through the
     * driver — prefix by prefix, EEXIST-tolerant.
     * Dispatch on the leaf instance so brix_sd_mkdir_maybe_cred finds the leaf
     * driver's mkdir_cred slot (decorators have only plain relays). */
    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        vfs_mkdir_req_t req;

        req.ctx = ctx;
        req.path = path;
        req.mode = mode;
        req.parents = parents;
        req.start = start;
        return vfs_mkdir_backend(&req, drv);
    }

    res = brix_ns_mkdir(ctx->log, ctx->root_canon,
                          brix_vfs_ctx_path(ctx), mode,
                          parents ? 1 : 0);
    if (res.status == BRIX_NS_OK) {
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_MKDIR, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    errno = res.sys_errno != 0 ? res.sys_errno : EIO;
    saved_errno = errno;
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_MKDIR, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}

/*
 * brix_vfs_chmod — change the resolved path's permission bits through the VFS
 * seam. Like brix_vfs_mkdir it delegates to the impersonation-aware confined
 * helper (brix_chmod_confined_canon) rather than a raw fchmodat, so under
 * impersonation the chmod is performed by the broker as the mapped user.
 */
ngx_int_t
brix_vfs_chmod(brix_vfs_ctx_t *ctx, mode_t mode)
{
    if (brix_vfs_require_write(ctx) != NGX_OK) {
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
        const brix_sd_driver_t *drv = brix_vfs_ctx_driver(ctx);
        if (drv != NULL) {
            brix_sd_ucred_t   store;
            brix_sd_cred_t    cred;
            brix_sd_setattr_t attr;
            ngx_int_t         chmod_rc;
            int               use_cred = 0, cred_err = 0;

            /* Zero before the gate: it fills only the active credential kind;
             * an unzeroed cred hands a garbage inactive pointer to the driver
             * cred slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
            ngx_memzero(&cred, sizeof(cred));

            if (brix_vfs_cred_gate_active(ctx)) {
                if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
                    != NGX_OK)
                {
                    errno = cred_err ? cred_err : EACCES;
                    return NGX_ERROR;
                }
            }
            if (drv->setattr == NULL) {
                brix_sd_ucred_wipe(&store);   /* resolved but unused; erase */
                return NGX_OK;
            }
            ngx_memzero(&attr, sizeof(attr));
            attr.set_mode = 1;
            attr.mode = mode;
            /* Dispatch on the leaf so brix_sd_setattr_maybe_cred finds the
             * leaf driver's setattr_cred slot (decorators relay to plain). */
            chmod_rc = brix_sd_setattr_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
                           brix_vfs_export_relative(ctx, brix_vfs_ctx_path(ctx)),
                           &attr, use_cred ? &cred : NULL) == NGX_OK
                       ? NGX_OK : NGX_ERROR;
            brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
            return chmod_rc;
        }
    }
    if (brix_chmod_confined_canon(ctx->log, ctx->root_canon,
                                    brix_vfs_ctx_path(ctx), mode) != 0) {
        return NGX_ERROR;   /* errno set by the helper */
    }
    return NGX_OK;
}

/*
 * brix_vfs_setattr — apply kXR_setattr (times and/or owner) to the resolved
 * path through the VFS seam. A non-POSIX backend routes to its setattr slot
 * (no-op success if it has none); the default POSIX path uses the
 * impersonation-aware confined utimensat/fchownat helper so under impersonation
 * the change is performed by the broker as the mapped user. The unified slot also
 * carries mode, so a backend satisfies chmod and setattr through one entry point —
 * kXR_setattr itself never sets mode (that is kXR_chmod's job).
 */
ngx_int_t
brix_vfs_setattr(brix_vfs_ctx_t *ctx, const brix_sd_setattr_t *attr)
{
    if (brix_vfs_require_write(ctx) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ctx->root_canon == NULL || attr == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    {
        const brix_sd_driver_t *drv = brix_vfs_ctx_driver(ctx);
        if (drv != NULL) {
            brix_sd_ucred_t store;
            brix_sd_cred_t  cred;
            ngx_int_t       setattr_rc;
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
                    return NGX_ERROR;
                }
            }
            if (drv->setattr == NULL) {
                brix_sd_ucred_wipe(&store);   /* resolved but unused; erase */
                return NGX_OK;   /* no mutable metadata — no-op success */
            }
            /* Dispatch on the leaf so brix_sd_setattr_maybe_cred finds the
             * leaf driver's setattr_cred slot (decorators relay to plain). */
            setattr_rc = brix_sd_setattr_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
                             brix_vfs_export_relative(ctx,
                                 brix_vfs_ctx_path(ctx)),
                             attr, use_cred ? &cred : NULL) == NGX_OK
                         ? NGX_OK : NGX_ERROR;
            brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
            return setattr_rc;
        }
    }

    {
        struct timespec times[2];
        times[0] = attr->atime;
        times[1] = attr->mtime;
        if (brix_setattr_confined_canon(ctx->log, ctx->root_canon,
                brix_vfs_ctx_path(ctx), attr->set_times, times,
                attr->set_owner, attr->uid, attr->gid) != 0) {
            return NGX_ERROR;
        }
        if (attr->set_mode
            && brix_chmod_confined_canon(ctx->log, ctx->root_canon,
                                           brix_vfs_ctx_path(ctx), attr->mode) != 0) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}
