/*
 * vfs_sync.c — VFS handle-level truncate and durability.
 *
 * WHAT: Implements brix_vfs_truncate() (resize an open handle to `length`),
 *       brix_vfs_sync() (flush an open handle to stable storage), and
 *       brix_vfs_file_read_advise() (advisory read-ahead hint on the handle).
 *
 * WHY:  kXR_truncate and the sync/commit step of writes (kXR_sync, WebDAV PUT
 *       finalisation) operate on an already-open handle rather than a path, so
 *       they live with the file-handle ops; truncate must also keep the handle's
 *       cached size in step with the file.
 *
 * HOW:  truncate validates the handle/fd and a non-negative length, runs a VFS
 *       I/O-core TRUNCATE job, and on success updates fh->size so later reads
 *       see the new length. sync validates the handle and runs a VFS I/O-core
 *       SYNC job. Both are unmetered handle operations (the surrounding write
 *       op records the metric) returning NGX_OK / NGX_ERROR with errno set.
 */
#include "vfs_internal.h"
#include "vfs_io_core.h"

/* Resize the open handle to `length` (ftruncate) and update the cached
 * fh->size. NGX_ERROR with errno set on a bad handle or negative length. */
ngx_int_t
brix_vfs_truncate(brix_vfs_file_t *fh, off_t length)
{
    brix_vfs_job_t job;

    if (fh == NULL || fh->obj.fd == NGX_INVALID_FILE || length < 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    /* phase-71: capability gate — a backend without CAP_TRUNCATE rejects resize
     * uniformly rather than issuing an ftruncate the driver cannot honor. */
    if (fh->obj.inst != NULL
        && !(brix_sd_caps(fh->obj.inst) & BRIX_SD_CAP_TRUNCATE))
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }

    brix_vfs_job_truncate_init(&job, fh->obj.fd, length);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        errno = job.io_errno;
        return NGX_ERROR;
    }

    fh->size = length;
    return NGX_OK;
}

/* Path-based truncate: resize the resolved ctx path to `length` WITHOUT opening a
 * write handle when the backend offers a path-native truncate. Write-gated.
 *
 * WHY:  Over a remote (root://) backend BriX auto-composes a write-stage tier; the
 *       old handler opened a WRITE handle to truncate, which staged the file (whole-
 *       file RECALL) and took an origin write-open that self-collides on commit —
 *       surfacing as kXR_Unsupported. A path-native truncate resizes the origin by
 *       name in one round-trip, no staging.
 *
 * HOW:  When the bound driver advertises truncate_path (remote xroot, directly or
 *       via the stage decorator's forwarder), dispatch on the LEAF instance through
 *       brix_sd_truncate_path_maybe_cred so per-user credentials reach the leaf's
 *       truncate_path_cred slot (decorators carry only plain relays). Otherwise
 *       (POSIX and any backend without the slot) fall back to the original
 *       open(O_WRITE)+ftruncate+close, preserving prior behavior exactly.
 *       Unmetered like brix_vfs_truncate — the kXR_truncate handler logs access. */
ngx_int_t
brix_vfs_truncate_path(brix_vfs_ctx_t *ctx, off_t length)
{
    const brix_sd_driver_t *drv;
    const char               *path;

    if (length < 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (brix_vfs_require_write(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    path = brix_vfs_ctx_path(ctx);
    drv  = brix_vfs_ctx_driver(ctx);

    if (drv != NULL && drv->truncate_path != NULL) {
        brix_sd_instance_t *leaf = brix_vfs_ns_leaf(ctx->sd);
        brix_sd_ucred_t     store;
        brix_sd_cred_t      cred;
        ngx_int_t           rc;
        int                 use_cred = 0, cred_err = 0, saved_errno;
        const char           *key;

        /* Zero before the gate: it fills only the active credential kind; an
         * unzeroed cred hands a garbage inactive pointer to the driver's slot. */
        ngx_memzero(&cred, sizeof(cred));

        if (brix_vfs_cred_gate_active(ctx)) {
            if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
                != NGX_OK)
            {
                errno = cred_err ? cred_err : EACCES;
                return NGX_ERROR;
            }
        }

        key = brix_vfs_export_relative(ctx, path);
        rc = brix_sd_truncate_path_maybe_cred(leaf, key, length,
                 use_cred ? &cred : NULL);
        saved_errno = errno;
        brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
        errno = saved_errno;
        return rc;
    }

    /* Fallback: no path-native truncate — open a write handle, resize, close. */
    {
        brix_vfs_file_t *fh;
        int                vfs_err = 0;

        fh = brix_vfs_open(ctx, BRIX_VFS_O_WRITE, &vfs_err);
        if (fh == NULL) {
            errno = vfs_err;
            return NGX_ERROR;
        }
        if (brix_vfs_truncate(fh, length) != NGX_OK) {
            int e = errno;
            brix_vfs_close(fh, ctx->log);
            errno = e;
            return NGX_ERROR;
        }
        brix_vfs_close(fh, ctx->log);
        return NGX_OK;
    }
}

/* Flush the open handle to stable storage (fsync). NGX_ERROR with errno set on
 * a bad handle or fsync failure. */
ngx_int_t
brix_vfs_sync(brix_vfs_file_t *fh)
{
    brix_vfs_job_t job;

    if (fh == NULL || fh->obj.fd == NGX_INVALID_FILE) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    brix_vfs_job_sync_init(&job, fh->obj.fd);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        errno = job.io_errno;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Advisory read-ahead hint on the open handle (phase-56 B-2). Dispatches to the
 * driver's read_advise slot; a backend without the slot succeeds as a no-op, so
 * callers hint unconditionally and never branch on backend type. */
ngx_int_t
brix_vfs_file_read_advise(brix_vfs_file_t *fh, off_t off, size_t len,
    int advice)
{
    if (fh == NULL || fh->obj.driver == NULL || off < 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (fh->obj.driver->read_advise == NULL) {
        return NGX_OK;
    }

    return fh->obj.driver->read_advise(&fh->obj, off, len, advice);
}
