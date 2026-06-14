/*
 * vfs_open.c — VFS open/close, handle lifecycle, and shared file helpers.
 *
 * WHAT: Implements xrootd_vfs_open()/xrootd_vfs_close() and the xrootd_vfs_file_*
 *       accessors (fd/path/size/mtime/from_cache/file_stat). Also hosts the
 *       cross-unit helpers declared in vfs_internal.h: xrootd_vfs_fill_stat()
 *       (struct stat -> xrootd_vfs_stat_t), xrootd_vfs_copy_path() (pool-dup a
 *       C string), xrootd_vfs_register_fd_cleanup() (close-on-pool-destroy), and
 *       xrootd_vfs_adopt_fd() (wrap an already-open fd in a handle).
 *
 * WHY:  Open is the one place that has to reconcile three concerns at once:
 *       write permission, the read-through cache, and kernel-enforced
 *       confinement. Concentrating that decision here keeps every other op file
 *       able to assume a valid, confined, already-fstat'd handle.
 *
 * HOW:  xrootd_vfs_open() re-verifies confinement, gates writes on
 *       ctx->allow_write, optionally pre-creates the parent dir tree
 *       (XROOTD_VFS_O_MKDIRPATH), then tries xrootd_cache_open() first. On a
 *       cache miss it translates flags via xrootd_vfs_open_flags() and walks the
 *       confinement cascade strongest-first: persistent rootfd +
 *       xrootd_open_beneath (openat2 RESOLVE_BENEATH), else root_canon +
 *       xrootd_open_confined_canon, else a raw open() reachable only for
 *       server-constructed paths with no export root. The resulting fd is
 *       wrapped by xrootd_vfs_adopt_fd(), which fstat()s it into the handle.
 */
#include "vfs_internal.h"
#include "../cache/open.h"
#include "../path/beneath.h"

/* Copy a struct stat into the protocol-neutral xrootd_vfs_stat_t (zeroes the
 * output first; sets is_directory/is_regular from the mode). No-op on NULL. */
void
xrootd_vfs_fill_stat(const struct stat *st, xrootd_vfs_stat_t *out)
{
    if (st == NULL || out == NULL) {
        return;
    }

    ngx_memzero(out, sizeof(*out));
    out->size = st->st_size;
    out->mtime = st->st_mtime;
    out->ctime = st->st_ctime;
    out->mode = (ngx_uint_t) st->st_mode;
    out->ino = st->st_ino;
    out->is_directory = S_ISDIR(st->st_mode) ? 1 : 0;
    out->is_regular = S_ISREG(st->st_mode) ? 1 : 0;
}

char *
xrootd_vfs_copy_path(ngx_pool_t *pool, const char *path)
{
    size_t  len;
    char   *copy;

    if (pool == NULL || path == NULL) {
        errno = EINVAL;
        return NULL;
    }

    len = strlen(path);
    copy = ngx_pnalloc(pool, len + 1);
    if (copy == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    ngx_memcpy(copy, path, len);
    copy[len] = '\0';
    return copy;
}

/* Arm an ngx_pool cleanup that closes fd when the pool is destroyed, so a
 * dup'd descriptor handed to a sendfile buffer never leaks. */
ngx_int_t
xrootd_vfs_register_fd_cleanup(ngx_pool_t *pool, ngx_fd_t fd,
    const char *path, ngx_log_t *log)
{
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;

    if (pool == NULL || fd == NGX_INVALID_FILE) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;
    clnf->fd = fd;
    clnf->name = (u_char *) (path != NULL ? path : "xrootd_vfs_file");
    clnf->log = log;

    return NGX_OK;
}

/* Wrap an already-open fd in a freshly pcalloc'd xrootd_vfs_file_t: fstat the
 * fd into the cached metadata, dup the path, and record from_cache/is_tls.
 * Used by both xrootd_vfs_open() and the cache layer's open path. */
ngx_int_t
xrootd_vfs_adopt_fd(xrootd_vfs_ctx_t *ctx, const char *path, ngx_fd_t fd,
    unsigned from_cache, xrootd_vfs_file_t **out)
{
    struct stat         st;
    xrootd_vfs_file_t  *fh;

    if (out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    *out = NULL;

    if (ctx == NULL || path == NULL || fd == NGX_INVALID_FILE) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (fstat(fd, &st) != 0) {
        return NGX_ERROR;
    }

    fh = ngx_pcalloc(ctx->pool, sizeof(*fh));
    if (fh == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    fh->path = xrootd_vfs_copy_path(ctx->pool, path);
    if (fh->path == NULL) {
        return NGX_ERROR;
    }

    fh->fd = fd;
    fh->pool = ctx->pool;
    fh->log = ctx->log;
    fh->ctx = ctx;
    fh->size = st.st_size;
    fh->mtime = st.st_mtime;
    fh->ctime = st.st_ctime;
    fh->ino = st.st_ino;
    fh->mode = st.st_mode;
    fh->from_cache = from_cache ? 1 : 0;
    fh->is_tls = ctx->is_tls;

    *out = fh;
    return NGX_OK;
}

static int
xrootd_vfs_open_flags(ngx_uint_t flags)
{
    int oflags;

    if ((flags & XROOTD_VFS_O_READ) && (flags & XROOTD_VFS_O_WRITE)) {
        oflags = O_RDWR;
    } else if (flags & XROOTD_VFS_O_WRITE) {
        oflags = O_WRONLY;
    } else {
        oflags = O_RDONLY;
    }

    if (flags & XROOTD_VFS_O_CREATE) {
        oflags |= O_CREAT;
    }
    if (flags & XROOTD_VFS_O_EXCL) {
        oflags |= O_EXCL;
    }
    if (flags & XROOTD_VFS_O_TRUNC) {
        oflags |= O_TRUNC;
    }
    if (flags & XROOTD_VFS_O_APPEND) {
        oflags |= O_APPEND;
    }

    return oflags;
}

/* For XROOTD_VFS_O_MKDIRPATH: create the target's parent directory chain
 * (confined under root_canon, mode 0755) before the file open is attempted. */
static ngx_int_t
xrootd_vfs_mkdir_parent_path(xrootd_vfs_ctx_t *ctx, const char *path)
{
    char  *parent;
    char  *slash;

    if (ctx->root_canon == NULL || path == NULL) {
        return NGX_OK;
    }

    parent = xrootd_vfs_copy_path(ctx->pool, path);
    if (parent == NULL) {
        return NGX_ERROR;
    }

    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return NGX_OK;
    }

    *slash = '\0';
    if (xrootd_mkdir_recursive_confined_canon(ctx->log, ctx->root_canon,
                                              parent, 0755, NULL) != 0)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Open the resolved ctx path under the confinement cascade. Returns a handle
 * or NULL with the syscall errno in *err_out. Cache hits short-circuit; writes
 * require ctx->allow_write. See the file header for the full open sequence. */
xrootd_vfs_file_t *
xrootd_vfs_open(xrootd_vfs_ctx_t *ctx, ngx_uint_t flags, int *err_out)
{
    const char         *path;
    int                 oflags;
    ngx_fd_t            fd;
    xrootd_vfs_file_t  *fh;
    ngx_int_t           rc;

    if (err_out != NULL) {
        *err_out = 0;
    }

    if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }

    if ((flags & XROOTD_VFS_O_WRITE) && !ctx->allow_write) {
        errno = EACCES;
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }

    path = xrootd_vfs_ctx_path(ctx);
    if ((flags & XROOTD_VFS_O_MKDIRPATH)
        && xrootd_vfs_mkdir_parent_path(ctx, path) != NGX_OK)
    {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }

    rc = xrootd_cache_open(ctx, flags, &fh);
    if (rc == NGX_OK) {
        xrootd_metric_cache_result(xrootd_vfs_metrics_proto(ctx), 1, 0);
        return fh;
    }
    if (rc == NGX_ERROR) {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }
    if (ctx->cache_enabled && !(flags & XROOTD_VFS_O_WRITE)
        && !(flags & XROOTD_VFS_O_NOCACHE))
    {
        xrootd_metric_cache_result(xrootd_vfs_metrics_proto(ctx), 0, 0);
    }

    oflags = xrootd_vfs_open_flags(flags);
    /*
     * Confinement cascade, strongest first:
     *   1. ctx->rootfd >= 0  → xrootd_open_beneath(): persistent per-worker
     *      O_PATH fd + openat2(RESOLVE_BENEATH).  This is the Phase 8 path and
     *      the case every real data-server request takes.
     *   2. root_canon only   → xrootd_open_confined_canon(): same openat2
     *      RESOLVE_BENEATH semantics but opens the rootfd per call.  Reached only
     *      by contexts that have a root string but no persistent fd (legacy
     *      callers being retired); still fully confined.
     *   3. neither            → raw open().  NOT a confinement bypass: this branch
     *      is only taken when the VFS ctx carries no root at all (e.g. an
     *      already-absolute, server-constructed path in a non-export context).
     *      `path` here is never a raw client path — client requests always set a
     *      root and therefore take branch 1 or 2.  If a root is present the raw
     *      open is unreachable.
     */
    if (ctx->rootfd >= 0) {
        fd = xrootd_open_beneath(ctx->rootfd, path, oflags, 0644);
    } else if (ctx->root_canon != NULL) {
        fd = xrootd_open_confined_canon(ctx->log, ctx->root_canon, path,
                                        oflags, 0644);
    } else {
        fd = open(path, oflags, 0644);
    }

    if (fd == NGX_INVALID_FILE) {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }

    if (xrootd_vfs_adopt_fd(ctx, path, fd, 0, &fh) != NGX_OK) {
        int err = errno;
        ngx_close_file(fd);
        if (err_out != NULL) {
            *err_out = err;
        }
        errno = err;
        return NULL;
    }

    return fh;
}

ngx_int_t
xrootd_vfs_close(xrootd_vfs_file_t *fh, ngx_log_t *log)
{
    if (fh == NULL || fh->fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (ngx_close_file(fh->fd) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log != NULL ? log : fh->log, ngx_errno,
                      "xrootd_vfs: close failed for \"%s\"",
                      fh->path != NULL ? fh->path : "-");
        fh->fd = NGX_INVALID_FILE;
        return NGX_ERROR;
    }

    fh->fd = NGX_INVALID_FILE;
    return NGX_OK;
}

ngx_fd_t
xrootd_vfs_file_fd(const xrootd_vfs_file_t *fh)
{
    return fh != NULL ? fh->fd : NGX_INVALID_FILE;
}

const char *
xrootd_vfs_file_path(const xrootd_vfs_file_t *fh)
{
    return (fh != NULL && fh->path != NULL) ? fh->path : "";
}

off_t
xrootd_vfs_file_size(const xrootd_vfs_file_t *fh)
{
    return fh != NULL ? fh->size : 0;
}

time_t
xrootd_vfs_file_mtime(const xrootd_vfs_file_t *fh)
{
    return fh != NULL ? fh->mtime : 0;
}

ngx_uint_t
xrootd_vfs_file_from_cache(const xrootd_vfs_file_t *fh)
{
    return (fh != NULL && fh->from_cache) ? 1 : 0;
}

ngx_int_t
xrootd_vfs_file_stat(const xrootd_vfs_file_t *fh, xrootd_vfs_stat_t *stat_out)
{
    struct stat st;

    if (fh == NULL || fh->fd == NGX_INVALID_FILE || stat_out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (fstat(fh->fd, &st) != 0) {
        return NGX_ERROR;
    }

    xrootd_vfs_fill_stat(&st, stat_out);
    return NGX_OK;
}
