/*
 * vfs_dir.c — VFS directory enumeration (opendir/readdir/closedir).
 *
 * WHAT: Implements brix_vfs_opendir(), brix_vfs_readdir(), and
 *       brix_vfs_closedir() over the opaque brix_vfs_dir_t handle. readdir
 *       yields one entry per call as a pooled, NUL-terminated ngx_str_t, with an
 *       optional lstat of the child filled into an brix_vfs_stat_t.
 *
 * WHY:  Directory listing (XRootD kXR_dirlist, WebDAV PROPFIND, S3 LIST) needs
 *       confinement, the "." / ".." filter, and a NGX_DONE end-of-stream signal
 *       to be handled once, the same way, for every protocol — rather than each
 *       front end driving opendir/readdir itself.
 *
 * HOW:  opendir re-verifies confinement, pcalloc's the handle on ctx->pool,
 *       dups the resolved path, and opens the C-library DIR*; the open itself is
 *       observed as BRIX_METRIC_OP_DIRLIST. readdir loops skipping "."/".."
 *       (and entries are distinguished from a real error via errno-cleared
 *       readdir, returning NGX_DONE when the stream ends), copies the name into
 *       the pool, and optionally builds "<dir>/<name>" for an lstat. closedir
 *       calls closedir(3) and nulls the handle so it is idempotent.
 */
#include "vfs_internal.h"
#include "core/compat/log_diag.h"

/* Shared opendir body. When `observe` is set the open is metered as OP_DIRLIST;
 * the quiet variant (observe=0) skips the metric/access-log entirely — for bulk
 * recursive walks (S3 ListObjects, WebDAV SEARCH) whose enclosing protocol op
 * already accounts for the traversal and would otherwise emit one phantom
 * OP_DIRLIST per visited subdirectory. */
static brix_vfs_dir_t *
brix_vfs_opendir_impl(brix_vfs_ctx_t *ctx, int *err_out, int observe)
{
    brix_vfs_dir_t *dh;
    const char       *path;
    uint64_t          start;
    int               saved_errno;

    start = brix_vfs_now_ns();

    if (err_out != NULL) {
        *err_out = 0;
    }

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        if (observe) {
            brix_vfs_observe_ctx_op(ctx, brix_vfs_ctx_path(ctx),
                                      BRIX_METRIC_OP_DIRLIST, NULL, 0,
                                      NGX_ERROR, saved_errno, start);
        }
        return NULL;
    }

    path = brix_vfs_ctx_path(ctx);
    dh = ngx_pcalloc(ctx->pool, sizeof(*dh));
    if (dh == NULL) {
        errno = ENOMEM;
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        if (observe) {
            brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DIRLIST, NULL,
                                      0, NGX_ERROR, saved_errno, start);
        }
        return NULL;
    }

    dh->path = brix_vfs_copy_path(ctx->pool, path);
    if (dh->path == NULL) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        if (observe) {
            brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DIRLIST, NULL,
                                      0, NGX_ERROR, saved_errno, start);
        }
        return NULL;
    }

    /* Non-POSIX backend: enumerate through the driver's directory iterator. */
    {
        const brix_sd_driver_t *drv = brix_vfs_ctx_driver(ctx);

        if (drv != NULL) {
            const char *logical = brix_vfs_export_relative(ctx, path);
            int         err = 0;

            if (drv->opendir == NULL) {
                errno = ENOTSUP;
            }
            dh->sd_dir = (drv->opendir != NULL)
                ? drv->opendir(ctx->sd, logical, &err) : NULL;
            if (dh->sd_dir == NULL) {
                saved_errno = (err != 0) ? err : errno;
                if (err_out != NULL) { *err_out = saved_errno; }
                if (observe) {
                    brix_vfs_observe_ctx_op(ctx, path,
                        BRIX_METRIC_OP_DIRLIST, NULL, 0, NGX_ERROR,
                        saved_errno, start);
                }
                return NULL;
            }
            dh->sd  = ctx->sd;
            dh->drv = drv;
            dh->sd_logical = brix_vfs_copy_path(ctx->pool, logical);
            dh->pool = ctx->pool;
            dh->log = ctx->log;
            if (observe) {
                brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DIRLIST,
                                          NULL, 0, NGX_OK, 0, start);
            }
            return dh;
        }
    }

    /* Open the directory AS THE MAPPED USER under impersonation (broker fdopendir)
     * so a 0700 user-owned / 0770 group-restricted dir the unprivileged worker
     * cannot itself open is enumerable by its legitimate owner/group-member; off
     * impersonation this is a bare opendir(). */
    dh->dir = brix_opendir_confined_canon(ctx->log, ctx->root_canon, path);
    if (dh->dir == NULL) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        if (observe) {
            brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_DIRLIST, NULL,
                                      0, NGX_ERROR, saved_errno, start);
        }
        return NULL;
    }

    dh->pool = ctx->pool;
    dh->log = ctx->log;
    dh->root_canon = ctx->root_canon;

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

/* Return the next entry: name as a pooled NUL-terminated ngx_str_t, plus an
 * optional lstat of the child. Skips "." and ".."; returns NGX_DONE at
 * end-of-stream and NGX_ERROR (errno set) on failure. */
ngx_int_t
brix_vfs_readdir(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_stat_t *stat_out)
{
    struct dirent *de;

    if (dh == NULL || name_out == NULL
        || (dh->dir == NULL && dh->sd_dir == NULL))
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    /* Non-POSIX backend: pull the next entry from the driver iterator and stat the
     * child through the same driver (skip a child that vanished mid-scan). */
    if (dh->sd_dir != NULL) {
        brix_sd_dirent_t de_sd;
        ngx_int_t          rc = dh->drv->readdir(dh->sd_dir, &de_sd);

        if (rc != NGX_OK) {
            return rc;                                 /* NGX_DONE / NGX_ERROR */
        }
        if (stat_out != NULL && dh->drv->stat != NULL) {
            char             child[PATH_MAX];
            brix_sd_stat_t sd_st;

            ngx_snprintf((u_char *) child, sizeof(child), "%s/%s%Z",
                         (dh->sd_logical[0] == '/' && dh->sd_logical[1] == '\0')
                             ? "" : dh->sd_logical, de_sd.name);
            if (dh->drv->stat(dh->sd, child, &sd_st) != NGX_OK) {
                return brix_vfs_readdir(dh, name_out, stat_out);   /* skip */
            }
            brix_vfs_sd_stat_fill(&sd_st, stat_out);
        }
        name_out->len = ngx_strlen(de_sd.name);
        name_out->data = ngx_pnalloc(dh->pool, name_out->len + 1);
        if (name_out->data == NULL) {
            errno = ENOMEM;
            return NGX_ERROR;
        }
        ngx_memcpy(name_out->data, de_sd.name, name_out->len + 1);
        return NGX_OK;
    }

    for ( ;; ) {
        errno = 0;
        de = readdir(dh->dir);
        if (de == NULL) {
            return errno == 0 ? NGX_DONE : NGX_ERROR;
        }

        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;
        }

        /* Per-entry stat is folded into the scan so a single bad entry SKIPS
         * rather than truncating the listing: a child that races an unlink
         * (ENOENT), or whose joined path is unrepresentable, is dropped and the
         * scan continues. (Only NGX_DONE/NGX_ERROR — true end/stream error —
         * stop the caller's loop.) */
        if (stat_out != NULL) {
            char         child[PATH_MAX];
            struct stat  st;
            int          n;

            n = snprintf(child, sizeof(child), "%s/%s", dh->path, de->d_name);
            if (n < 0 || (size_t) n >= sizeof(child)) {
                continue;
            }
            /* lstat the child AS THE MAPPED USER (broker-routed) so enumerating a
             * group-restricted dir does not EACCES per child as the worker. */
            if (brix_lstat_confined_canon(dh->log, dh->root_canon, child,
                                            &st, 1) != 0) {
                continue;
            }
            brix_vfs_fill_stat(&st, stat_out);
        }

        break;
    }

    name_out->len = strlen(de->d_name);
    name_out->data = ngx_pnalloc(dh->pool, name_out->len + 1);
    if (name_out->data == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memcpy(name_out->data, de->d_name, name_out->len);
    name_out->data[name_out->len] = '\0';

    return NGX_OK;
}

/* Yield the next entry's name plus its KIND from the readdir d_type, with no
 * per-entry stat — for callers that classify dir-vs-file on the fast path and
 * only stat (via brix_vfs_probe) on a DT_UNKNOWN filesystem. Skips "."/"..";
 * NGX_DONE at end-of-stream, NGX_ERROR (errno set) on failure. */
ngx_int_t
brix_vfs_readdir_kind(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_dirent_kind_t *kind_out)
{
    struct dirent *de;

    if (dh == NULL || name_out == NULL
        || (dh->dir == NULL && dh->sd_dir == NULL))
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (dh->sd_dir != NULL) {
        brix_sd_dirent_t de_sd;
        ngx_int_t          rc = dh->drv->readdir(dh->sd_dir, &de_sd);

        if (rc != NGX_OK) {
            return rc;
        }
        if (kind_out != NULL) {
            char             child[PATH_MAX];
            brix_sd_stat_t sd_st;

            ngx_snprintf((u_char *) child, sizeof(child), "%s/%s%Z",
                         (dh->sd_logical[0] == '/' && dh->sd_logical[1] == '\0')
                             ? "" : dh->sd_logical, de_sd.name);
            *kind_out = (dh->drv->stat != NULL
                         && dh->drv->stat(dh->sd, child, &sd_st) == NGX_OK)
                ? (sd_st.is_dir ? BRIX_VFS_DT_DIR : BRIX_VFS_DT_REG)
                : BRIX_VFS_DT_UNKNOWN;
        }
        name_out->len = ngx_strlen(de_sd.name);
        name_out->data = ngx_pnalloc(dh->pool, name_out->len + 1);
        if (name_out->data == NULL) {
            errno = ENOMEM;
            return NGX_ERROR;
        }
        ngx_memcpy(name_out->data, de_sd.name, name_out->len + 1);
        return NGX_OK;
    }

    for ( ;; ) {
        errno = 0;
        de = readdir(dh->dir);
        if (de == NULL) {
            return errno == 0 ? NGX_DONE : NGX_ERROR;
        }

        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;
        }
        break;
    }

    if (kind_out != NULL) {
        switch (de->d_type) {
        case DT_DIR:     *kind_out = BRIX_VFS_DT_DIR;     break;
        case DT_REG:     *kind_out = BRIX_VFS_DT_REG;     break;
        case DT_UNKNOWN: *kind_out = BRIX_VFS_DT_UNKNOWN; break;
        default:         *kind_out = BRIX_VFS_DT_OTHER;   break;
        }
    }

    name_out->len = strlen(de->d_name);
    name_out->data = ngx_pnalloc(dh->pool, name_out->len + 1);
    if (name_out->data == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memcpy(name_out->data, de->d_name, name_out->len);
    name_out->data[name_out->len] = '\0';

    return NGX_OK;
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

/* brix_vfs_enumerate_catalog — driver-agnostic backend-catalog enumeration
 * (inventory/drift). Dispatches to the bound driver's optional `enumerate` verb;
 * a backend with no native object catalog (POSIX — the namespace IS the catalog)
 * leaves the verb NULL, and this reports ENOTSUP via NGX_DECLINED so the engine
 * falls back to a namespace walk. See vfs.h. */
ngx_int_t
brix_vfs_enumerate_catalog(brix_sd_instance_t *sd, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    if (sd == NULL || sd->driver == NULL || sd->driver->enumerate == NULL) {
        errno = ENOTSUP;
        return NGX_DECLINED;
    }
    return sd->driver->enumerate(sd, want_stat, cb, ctx);
}
