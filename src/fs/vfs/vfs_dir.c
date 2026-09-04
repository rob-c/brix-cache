/*
 * vfs_dir.c — VFS directory handle lifecycle (opendir/closedir).
 *
 * WHAT: Implements brix_vfs_opendir(), brix_vfs_opendir_quiet(),
 *       brix_vfs_dir_fd(), and brix_vfs_closedir() over the opaque
 *       brix_vfs_dir_t handle. The readdir family lives in vfs_dir_iter.c.
 *
 * WHY:  Directory listing (XRootD kXR_dirlist, WebDAV PROPFIND, S3 LIST) needs
 *       confinement and driver-plane dispatch handled once, the same way, for
 *       every protocol — rather than each front end driving opendir itself.
 *
 * HOW:  opendir re-verifies confinement, pcalloc's the handle on ctx->pool,
 *       dups the resolved path, and opens the C-library DIR* (or the driver's
 *       opendir slot); the open itself is observed as BRIX_METRIC_OP_DIRLIST.
 *       closedir calls closedir(3) (or the driver slot) and nulls the handle
 *       so it is idempotent.
 */
#include "vfs_internal.h"
#include "core/compat/log_diag.h"
#include "auth/impersonate/impersonate.h"

/* vfs_opendir_fail — shared error tail for the opendir body.
 *
 * WHAT: Reports a failed opendir: copies `err` into *err_out (when the caller
 *       asked for it), meters the failure as OP_DIRLIST when `observe` is set,
 *       and returns NULL for the caller to relay.
 * WHY:  Every early-out of the opendir body ends the same way; folding the
 *       report into one helper keeps the body's control flow flat.
 * HOW:  Pure reporting — errno is deliberately NOT touched here so each call
 *       site preserves exactly the errno state the pre-refactor code left; the
 *       observed path is the ctx's resolved path (what every caller reports). */
static brix_vfs_dir_t *
vfs_opendir_fail(brix_vfs_ctx_t *ctx, int err, int observe, uint64_t start,
    int *err_out)
{
    if (err_out != NULL) {
        *err_out = err;
    }
    if (observe) {
        brix_vfs_observe_ctx_op(ctx, brix_vfs_ctx_path(ctx),
                                  BRIX_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, err, start);
    }
    return NULL;
}

/* vfs_dir_route — the SECURITY SEAM: export confinement + plane selection.
 *
 * WHAT: Verifies the resolved ctx path is confined to the export root, then
 *       selects the enumeration plane: a non-POSIX driver iterator (*drv_out
 *       set) or the confined POSIX/broker opendir (*drv_out NULL).
 * WHY:  Confinement MUST be re-verified before any directory is opened, and
 *       the driver-vs-broker decision must live in exactly one place so no
 *       future path can enumerate an unconfined directory.
 * HOW:  brix_vfs_require_confined() gates everything; on failure *err carries
 *       its errno for the caller's report (errno itself is left untouched). */
static ngx_int_t
vfs_dir_route(brix_vfs_ctx_t *ctx, const brix_sd_driver_t **drv_out, int *err)
{
    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        *err = errno;
        return NGX_ERROR;
    }
    *drv_out = brix_vfs_ctx_driver(ctx);
    return NGX_OK;
}

/* vfs_dir_open_driver — open a non-POSIX backend's directory iterator.
 *
 * WHAT: Resolves the export-relative logical path, loads the per-user backend
 *       credential when the export is credential-scoped, and opens the leaf
 *       driver's directory iterator into dh->sd_dir, filling the handle's
 *       driver-plane fields.
 * WHY:  Object/remote backends have no DIR*; enumeration goes through the
 *       driver's opendir/readdir verbs instead of the confined POSIX path.
 * HOW:  Returns NGX_OK, or NGX_ERROR with *err set to the errno to report
 *       (errno itself only set where the pre-refactor code set it: the
 *       credential-load failure). Dispatches on the leaf instance so
 *       brix_sd_opendir_maybe_cred finds the leaf driver's opendir_cred slot
 *       (decorators have only plain relays). */
static ngx_int_t
vfs_dir_open_driver(brix_vfs_ctx_t *ctx, brix_vfs_dir_t *dh,
    const brix_sd_driver_t *drv, const char *path, int *err_out)
{
    char              physical[PATH_MAX];
    char              canonical[PATH_MAX];
    brix_sd_ucred_t   store;
    brix_sd_cred_t    cred;
    int               use_cred = 0, cred_err = 0;
    int               err = 0;

    /* Zero before the gate: it fills only the active credential kind; an
     * unzeroed cred hands a garbage inactive pointer to the driver's cred
     * slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
    ngx_memzero(&cred, sizeof(cred));

    if (brix_path_resolved_to_pfn(ctx, path, physical, sizeof(physical))
        != NGX_OK)
    {
        *err_out = errno;
        return NGX_ERROR;
    }
    if (brix_path_pfn_to_lfn(ctx, physical, canonical, sizeof(canonical))
        != NGX_OK)
    {
        *err_out = errno;
        return NGX_ERROR;
    }

    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
            != NGX_OK)
        {
            *err_out = cred_err ? cred_err : EACCES;
            errno = *err_out;
            return NGX_ERROR;
        }
    }

    if (drv->opendir == NULL) {
        errno = ENOTSUP;
    }
    dh->sd_dir = (drv->opendir != NULL)
        ? brix_sd_opendir_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
              physical, &err, use_cred ? &cred : NULL)
        : NULL;
    brix_sd_ucred_wipe(&store);   /* secret consumed by opendir; erase (A-4/T4) */
    if (dh->sd_dir == NULL) {
        *err_out = (err != 0) ? err : errno;
        return NGX_ERROR;
    }

    dh->sd  = ctx->sd;
    dh->drv = drv;
    dh->ctx = ctx;
    dh->sd_logical = brix_vfs_copy_path(ctx->pool, canonical);
    dh->sd_physical = brix_vfs_copy_path(ctx->pool, physical);
    if (dh->sd_logical == NULL || dh->sd_physical == NULL) {
        if (drv->closedir != NULL) {
            (void) drv->closedir(dh->sd_dir);
        }
        dh->sd_dir = NULL;
        *err_out = errno;
        return NGX_ERROR;
    }
    dh->pool = ctx->pool;
    dh->log = ctx->log;
    return NGX_OK;
}

/* vfs_dir_open_confined — the confined POSIX/broker opendir (do NOT weaken).
 *
 * WHAT: Opens dh->dir under export-root confinement and fills the handle's
 *       POSIX-plane fields.
 * WHY:  brix_opendir_confined_canon is the openat2 RESOLVE_IN_ROOT path from
 *       the symlink-escape fix — an outward symlink inside an export must stay
 *       invisible — and under impersonation it opens AS THE MAPPED USER
 *       (broker fdopendir) so a 0700 user-owned / 0770 group-restricted dir
 *       the unprivileged worker cannot itself open is enumerable by its
 *       legitimate owner/group-member; off impersonation it is a bare
 *       opendir().
 * HOW:  Returns NGX_OK, or NGX_ERROR with errno left exactly as the confined
 *       open set it. */
static ngx_int_t
vfs_dir_open_confined(brix_vfs_ctx_t *ctx, brix_vfs_dir_t *dh,
    const char *path)
{
    dh->dir = (ctx->rootfd >= 0)
              ? brix_opendir_confined_canon_at(ctx->log, ctx->rootfd,
                                                 ctx->root_canon, path)
              : brix_opendir_confined_canon(ctx->log, ctx->root_canon, path);
    if (dh->dir == NULL) {
        return NGX_ERROR;
    }

    dh->pool = ctx->pool;
    dh->log = ctx->log;
    dh->root_canon = ctx->root_canon;
    return NGX_OK;
}

/* Shared opendir body. When `observe` is set the open is metered as OP_DIRLIST;
 * the quiet variant (observe=0) skips the metric/access-log entirely — for bulk
 * recursive walks (S3 ListObjects, WebDAV SEARCH) whose enclosing protocol op
 * already accounts for the traversal and would otherwise emit one phantom
 * OP_DIRLIST per visited subdirectory. */
static brix_vfs_dir_t *
brix_vfs_opendir_impl(brix_vfs_ctx_t *ctx, int *err_out, int observe)
{
    brix_vfs_dir_t           *dh;
    const char               *path;
    const brix_sd_driver_t   *drv = NULL;
    uint64_t                  start;
    int                       err = 0;

    start = brix_vfs_now_ns();

    if (err_out != NULL) {
        *err_out = 0;
    }

    if (brix_vfs_require_authorized_lookup(ctx) != NGX_OK) {
        return vfs_opendir_fail(ctx, errno, observe, start, err_out);
    }

    if (vfs_dir_route(ctx, &drv, &err) != NGX_OK) {
        return vfs_opendir_fail(ctx, err, observe, start, err_out);
    }

    path = brix_vfs_ctx_path(ctx);
    dh = ngx_pcalloc(ctx->pool, sizeof(*dh));
    if (dh == NULL) {
        errno = ENOMEM;
        return vfs_opendir_fail(ctx, ENOMEM, observe, start, err_out);
    }

    dh->path = brix_vfs_copy_path(ctx->pool, path);
    if (dh->path == NULL) {
        return vfs_opendir_fail(ctx, errno, observe, start, err_out);
    }

    if (drv != NULL) {
        /* Non-POSIX backend: enumerate through the driver's iterator. */
        if (vfs_dir_open_driver(ctx, dh, drv, path, &err) != NGX_OK) {
            return vfs_opendir_fail(ctx, err, observe, start, err_out);
        }
    } else if (vfs_dir_open_confined(ctx, dh, path) != NGX_OK) {
        return vfs_opendir_fail(ctx, errno, observe, start, err_out);
    }

    if (observe) {
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_OK, 0, start);
    }
    return dh;
}

/* Open the resolved ctx directory under confinement. Returns a pooled handle or
 * NULL with the errno in *err_out; the open is metered as OP_DIRLIST. */
brix_vfs_dir_t *
brix_vfs_opendir(brix_vfs_ctx_t *ctx, int *err_out)
{
    return brix_vfs_opendir_impl(ctx, err_out, 1 /* observe */);
}

/* Non-metered confined opendir for bulk recursive walks (no OP_DIRLIST emitted —
 * the enclosing protocol op accounts for the whole traversal). Otherwise
 * identical to brix_vfs_opendir. */
brix_vfs_dir_t *
brix_vfs_opendir_quiet(brix_vfs_ctx_t *ctx, int *err_out)
{
    return brix_vfs_opendir_impl(ctx, err_out, 0 /* quiet */);
}

/* The open directory's fd (for a dirfd-relative entry openat that must remain in
 * the same impersonation-confined directory). NGX_INVALID_FILE if unavailable. */
ngx_fd_t
brix_vfs_dir_fd(const brix_vfs_dir_t *dh)
{
    return (dh != NULL && dh->dir != NULL) ? dirfd(dh->dir) : NGX_INVALID_FILE;
}

/* Close the directory stream and null the handle (idempotent). Logs and returns
 * NGX_ERROR if closedir(3) fails. */
ngx_int_t
brix_vfs_closedir(brix_vfs_dir_t *dh, ngx_log_t *log)
{
    if (dh == NULL || (dh->dir == NULL && dh->sd_dir == NULL)) {
        return NGX_OK;
    }

    if (dh->sd_dir != NULL) {
        ngx_int_t rc = (dh->drv->closedir != NULL)
            ? dh->drv->closedir(dh->sd_dir) : NGX_OK;

        dh->sd_dir = NULL;
        return rc;
    }

    if (closedir(dh->dir) != 0) {
        BRIX_DIAG_ERR(log != NULL ? log : dh->log, errno,
            "xrootd[disk]: closedir failed for \"%s\"",
            "the underlying directory stream returned an error on close — "
            "usually an I/O error on the backing storage",
            "check dmesg and the filesystem health for that path; the OS "
            "reason is appended below",
            dh->path != NULL ? dh->path : "-");
        dh->dir = NULL;
        return NGX_ERROR;
    }

    dh->dir = NULL;
    return NGX_OK;
}
