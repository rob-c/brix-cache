/*
 * vfs_dir.c — VFS directory enumeration (opendir/readdir/closedir).
 *
 * WHAT: Implements xrootd_vfs_opendir(), xrootd_vfs_readdir(), and
 *       xrootd_vfs_closedir() over the opaque xrootd_vfs_dir_t handle. readdir
 *       yields one entry per call as a pooled, NUL-terminated ngx_str_t, with an
 *       optional lstat of the child filled into an xrootd_vfs_stat_t.
 *
 * WHY:  Directory listing (XRootD kXR_dirlist, WebDAV PROPFIND, S3 LIST) needs
 *       confinement, the "." / ".." filter, and a NGX_DONE end-of-stream signal
 *       to be handled once, the same way, for every protocol — rather than each
 *       front end driving opendir/readdir itself.
 *
 * HOW:  opendir re-verifies confinement, pcalloc's the handle on ctx->pool,
 *       dups the resolved path, and opens the C-library DIR*; the open itself is
 *       observed as XROOTD_METRIC_OP_DIRLIST. readdir loops skipping "."/".."
 *       (and entries are distinguished from a real error via errno-cleared
 *       readdir, returning NGX_DONE when the stream ends), copies the name into
 *       the pool, and optionally builds "<dir>/<name>" for an lstat. closedir
 *       calls closedir(3) and nulls the handle so it is idempotent.
 */
#include "vfs_internal.h"
#include "../compat/log_diag.h"

/* Open the resolved ctx directory under confinement. Returns a pooled handle or
 * NULL with the errno in *err_out; the open is metered as OP_DIRLIST. */
xrootd_vfs_dir_t *
xrootd_vfs_opendir(xrootd_vfs_ctx_t *ctx, int *err_out)
{
    xrootd_vfs_dir_t *dh;
    const char       *path;
    uint64_t          start;
    int               saved_errno;

    start = xrootd_vfs_now_ns();

    if (err_out != NULL) {
        *err_out = 0;
    }

    if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        xrootd_vfs_observe_ctx_op(ctx, xrootd_vfs_ctx_path(ctx),
                                  XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NULL;
    }

    path = xrootd_vfs_ctx_path(ctx);
    dh = ngx_pcalloc(ctx->pool, sizeof(*dh));
    if (dh == NULL) {
        errno = ENOMEM;
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NULL;
    }

    dh->path = xrootd_vfs_copy_path(ctx->pool, path);
    if (dh->path == NULL) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NULL;
    }

    /* Open the directory AS THE MAPPED USER under impersonation (broker fdopendir)
     * so a 0700 user-owned / 0770 group-restricted dir the unprivileged worker
     * cannot itself open is enumerable by its legitimate owner/group-member; off
     * impersonation this is a bare opendir(). */
    dh->dir = xrootd_opendir_confined_canon(ctx->log, ctx->root_canon, path);
    if (dh->dir == NULL) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NULL;
    }

    dh->pool = ctx->pool;
    dh->log = ctx->log;
    dh->root_canon = ctx->root_canon;

    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                              NGX_OK, 0, start);
    return dh;
}

/* Return the next entry: name as a pooled NUL-terminated ngx_str_t, plus an
 * optional lstat of the child. Skips "." and ".."; returns NGX_DONE at
 * end-of-stream and NGX_ERROR (errno set) on failure. */
ngx_int_t
xrootd_vfs_readdir(xrootd_vfs_dir_t *dh, ngx_str_t *name_out,
    xrootd_vfs_stat_t *stat_out)
{
    struct dirent *de;

    if (dh == NULL || dh->dir == NULL || name_out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
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

    name_out->len = strlen(de->d_name);
    name_out->data = ngx_pnalloc(dh->pool, name_out->len + 1);
    if (name_out->data == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memcpy(name_out->data, de->d_name, name_out->len);
    name_out->data[name_out->len] = '\0';

    if (stat_out != NULL) {
        char         child[PATH_MAX];
        struct stat  st;
        int          n;

        n = snprintf(child, sizeof(child), "%s/%s", dh->path, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child)) {
            errno = ENAMETOOLONG;
            return NGX_ERROR;
        }

        /* lstat the child AS THE MAPPED USER (broker-routed) so enumerating a
         * group-restricted dir does not EACCES per child as the worker. */
        if (xrootd_lstat_confined_canon(dh->log, dh->root_canon, child,
                                        &st, 1) != 0) {
            return NGX_ERROR;
        }

        xrootd_vfs_fill_stat(&st, stat_out);
    }

    return NGX_OK;
}

/* Close the directory stream and null the handle (idempotent). Logs and returns
 * NGX_ERROR if closedir(3) fails. */
ngx_int_t
xrootd_vfs_closedir(xrootd_vfs_dir_t *dh, ngx_log_t *log)
{
    if (dh == NULL || dh->dir == NULL) {
        return NGX_OK;
    }

    if (closedir(dh->dir) != 0) {
        XROOTD_DIAG_ERR(log != NULL ? log : dh->log, errno,
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
