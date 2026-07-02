/*
 * vfs_open.c — VFS open/close, handle lifecycle, and shared file helpers.
 *
 * WHAT: Implements xrootd_vfs_open()/xrootd_vfs_close() and the xrootd_vfs_file_*
 *       accessors (fd/path/size/mtime/from_cache/file_stat). Also hosts the
 *       cross-unit helpers declared in vfs_internal.h: xrootd_vfs_fill_stat()
 *       (struct stat -> xrootd_vfs_stat_t), xrootd_vfs_copy_path() (pool-dup a
 *       C string) and xrootd_vfs_adopt_fd() (wrap an already-open fd in a
 *       handle).
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
#include "vfs_backend_registry.h"
#include "cache/open.h"
#include "path/beneath.h"
#include "compat/log_diag.h"

/* Populate a per-request xrootd_vfs_ctx_t with the fields the HTTP front ends
 * (WebDAV, S3) set identically: a transient (rootfd = -1) confined open of an
 * already-resolved canonical path. Zeroes the ctx first, then fills pool/log,
 * the metrics proto, the export + cache roots (deriving cache_enabled), the
 * write gate, the TLS flag, the identity, and the resolved path (is_confined).
 * Callers may still adjust individual fields afterwards (e.g. cache_writethrough
 * config). Kept HTTP-agnostic on purpose so the header stays stream-includable —
 * callers pass pool/log/is_tls extracted from their own request object. */
void
xrootd_vfs_ctx_init(xrootd_vfs_ctx_t *vctx, ngx_pool_t *pool, ngx_log_t *log,
    xrootd_proto_t proto, const char *root_canon, const char *cache_root_canon,
    int allow_write, int is_tls, xrootd_identity_t *identity,
    const char *resolved_path)
{
    if (vctx == NULL) {
        return;
    }

    ngx_memzero(vctx, sizeof(*vctx));
    vctx->rootfd = -1;
    vctx->pool = pool;
    vctx->log = log;
    vctx->metrics_proto = proto;
    vctx->root_canon = root_canon;
    /* Resolve the export's selected storage backend (NULL ⇒ default POSIX) so
     * every VFS op on this ctx routes through the driver without each handler
     * threading the instance. Per-worker, lazily created on first use. */
    vctx->sd = xrootd_vfs_backend_resolve(root_canon, log);
    vctx->cache_root_canon = cache_root_canon;
    vctx->cache_enabled =
        (cache_root_canon != NULL && cache_root_canon[0] != '\0') ? 1 : 0;
    vctx->allow_write = allow_write ? 1 : 0;
    vctx->is_tls = is_tls ? 1 : 0;
    vctx->identity = identity;
    if (resolved_path != NULL) {
        vctx->resolved.resolved.data = (u_char *) resolved_path;
        vctx->resolved.resolved.len = ngx_strlen(resolved_path);
        vctx->resolved.is_confined = 1;
    }
}

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
    out->atime = st->st_atime;
    out->mode = (ngx_uint_t) st->st_mode;
    out->ino = st->st_ino;
    out->dev = st->st_dev;
    out->uid = st->st_uid;
    out->gid = st->st_gid;
    out->blocks = st->st_blocks;
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

/* Wrap an already-open fd in a freshly pcalloc'd xrootd_vfs_file_t: fstat the
 * fd into the cached metadata, dup the path, and record from_cache/is_tls.
 * `writable` gates the stat_current fast path (set only for read-only handles).
 * Used by both xrootd_vfs_open() and the cache layer's open path. */
ngx_int_t
xrootd_vfs_adopt_fd(xrootd_vfs_ctx_t *ctx, const char *path, ngx_fd_t fd,
    unsigned from_cache, unsigned writable, xrootd_vfs_file_t **out)
{
    xrootd_sd_stat_t    st;
    xrootd_sd_obj_t     obj;
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

    /* Capture the open-time metadata through the backend's fstat slot rather
     * than a direct fstat(2): the VFS records the cached size/mtime/etc. but
     * leaves the syscall to the storage driver. */
    xrootd_vfs_ctx_sd_obj(ctx, fd, &obj);
    if (obj.driver->fstat == NULL || obj.driver->fstat(&obj, &st) != NGX_OK) {
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

    fh->obj = obj;          /* backend object built above (driver + inst + fd) */
    fh->pool = ctx->pool;
    fh->log = ctx->log;
    fh->ctx = ctx;
    fh->size = st.size;
    fh->mtime = st.mtime;
    fh->ctime = st.ctime;
    fh->ino = st.ino;
    fh->mode = st.mode;
    fh->from_cache = from_cache ? 1 : 0;
    fh->is_tls = ctx->is_tls;
    /* Trust the open-time metadata for stat() only on a read-only handle: the
     * file cannot change through it, so the fstat above stays authoritative for
     * the handle's lifetime. A writable handle leaves this 0 so xrootd_vfs_file_stat()
     * always issues a live fstat (its bytes/mtime/size move as it is written). */
    fh->stat_current = writable ? 0 : 1;

    *out = fh;
    return NGX_OK;
}

/* xrootd_vfs_adopt_obj — build a handle from an object the backend's open slot
 * already produced, PRESERVING its per-open state (e.g. an object backend's
 * block map / metadata), rather than rebuilding from a bare fd (which would drop
 * that state). Captures open-time metadata via the object's own fstat slot, then
 * moves the object into the handle by value. A heap-allocated shell (driver set
 * obj->heap_shell, e.g. pblock's malloc'd object) is freed once copied; the
 * per-open `state` lives on and is released by driver->close at handle close.
 * Used for the non-POSIX storage drivers; POSIX keeps the adopt_fd path. Also
 * the cache hit-serve path (src/cache/open.c) adopts a cache-storage driver
 * object — hence public (declared in vfs.h). */
ngx_int_t
xrootd_vfs_adopt_obj(xrootd_vfs_ctx_t *ctx, const char *path,
    xrootd_sd_obj_t *o, unsigned writable, xrootd_vfs_file_t **out);

/* xrootd_vfs_export_relative — the export-root-relative ("logical") form of a
 * confined path, which is what an inst-keyed storage-driver op expects (per the
 * SD seam contract). Some callers (WebDAV/S3) resolve to an absolute path under
 * root_canon; strip that prefix so a non-POSIX backend keys its namespace on the
 * logical path. Returns `path` unchanged when it is not under root_canon.
 * Declared in vfs_internal.h; shared with vfs_staged.c. */
/* Path-based form: strip `root_canon` (an absolute export root) from `path`. */
const char *
xrootd_vfs_export_relative_root(const char *path, const char *root_canon)
{
    size_t rlen;

    if (root_canon == NULL || path == NULL) {
        return path;
    }
    rlen = ngx_strlen(root_canon);
    if (rlen == 0 || ngx_strncmp(path, root_canon, rlen) != 0) {
        return path;
    }
    if (path[rlen] == '/') {
        return path + rlen;          /* "/sub/file"  */
    }
    if (path[rlen] == '\0') {
        return "/";                  /* the export root itself */
    }
    return path;                     /* a sibling that merely shares the prefix */
}

const char *
xrootd_vfs_export_relative(const xrootd_vfs_ctx_t *ctx, const char *path)
{
    return xrootd_vfs_export_relative_root(path, ctx->root_canon);
}

ngx_int_t
xrootd_vfs_adopt_obj(xrootd_vfs_ctx_t *ctx, const char *path,
    xrootd_sd_obj_t *o, unsigned writable, xrootd_vfs_file_t **out)
{
    xrootd_sd_stat_t   st;
    xrootd_vfs_file_t *fh;

    *out = NULL;
    if (ctx == NULL || path == NULL || o == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (o->driver->fstat == NULL || o->driver->fstat(o, &st) != NGX_OK) {
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

    fh->obj = *o;                  /* driver + instance + fd + per-open state */
    if (o->heap_shell) {
        free(o);                   /* shell copied into fh->obj; release it */
    }
    fh->obj.heap_shell = 0;        /* fh->obj is embedded, not a heap shell */

    fh->pool = ctx->pool;
    fh->log = ctx->log;
    fh->ctx = ctx;
    fh->size = st.size;
    fh->mtime = st.mtime;
    fh->ctime = st.ctime;
    fh->ino = st.ino;
    fh->mode = st.mode;
    fh->from_cache = 0;
    fh->is_tls = ctx->is_tls;
    fh->stat_current = writable ? 0 : 1;

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

/* Map the VFS open flags to the backend-neutral SD open flags the driver open
 * slot consumes (the driver maps them to O_* itself). 1:1 with the O_* mapping
 * above, so a driver-routed open is byte-identical to the legacy beneath open. */
static int
xrootd_vfs_to_sd_flags(ngx_uint_t flags)
{
    int sd = 0;

    if (flags & XROOTD_VFS_O_READ)   { sd |= XROOTD_SD_O_READ; }
    if (flags & XROOTD_VFS_O_WRITE)  { sd |= XROOTD_SD_O_WRITE; }
    if (flags & XROOTD_VFS_O_CREATE) { sd |= XROOTD_SD_O_CREATE; }
    if (flags & XROOTD_VFS_O_EXCL)   { sd |= XROOTD_SD_O_EXCL; }
    if (flags & XROOTD_VFS_O_TRUNC)  { sd |= XROOTD_SD_O_TRUNC; }
    if (flags & XROOTD_VFS_O_APPEND) { sd |= XROOTD_SD_O_APPEND; }

    return sd;
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
     * A non-POSIX storage backend (e.g. pblock) owns its own namespace and
     * confinement, so route EVERY open through its driver and adopt the returned
     * object (carrying its per-open state). This must run before the POSIX
     * confinement cascade below: that cascade opens a bare POSIX fd (via
     * open_beneath / confined_canon / raw open) which this backend's fstat/read
     * slots cannot interpret — adopting such an fd under a non-POSIX driver would
     * dereference a NULL per-open state. POSIX (the default driver, or an unset
     * backend) falls through to the cascade unchanged.
     */
    if (ctx->sd != NULL && ctx->sd->driver != xrootd_sd_default_driver()
        && ctx->sd->driver->open != NULL)
    {
        xrootd_sd_obj_t *o;
        int              sderr = 0;

        o = ctx->sd->driver->open(ctx->sd,
                                  xrootd_vfs_export_relative(ctx, path),
                                  xrootd_vfs_to_sd_flags(flags), 0644, &sderr);
        if (o == NULL) {
            if (err_out != NULL) {
                *err_out = sderr;
            }
            errno = sderr;
            return NULL;
        }
        if (xrootd_vfs_adopt_obj(ctx, path, o,
                (flags & XROOTD_VFS_O_WRITE) ? 1u : 0u, &fh) != NGX_OK)
        {
            int err = errno;

            o->driver->close(o);
            if (o->heap_shell) {
                free(o);
            }
            if (err_out != NULL) {
                *err_out = err;
            }
            errno = err;
            return NULL;
        }
        return fh;
    }

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
        /*
         * Hot path: route the confined open through the Storage Driver. A
         * pool-lived POSIX instance borrows the persistent rootfd (no extra
         * syscall, no fd ownership transfer); the driver performs the
         * RESOLVE_BENEATH open. The instance is cached on ctx->sd for reuse
         * across opens on this ctx. driver->open's fstat/obj are discarded —
         * adopt_fd re-wraps the returned fd below — keeping one handle-build path.
         */
        if (ctx->sd == NULL) {
            ctx->sd = xrootd_sd_posix_borrow_instance(ctx->pool, ctx->log,
                                                      ctx->rootfd,
                                                      ctx->root_canon);
        }
        if (ctx->sd != NULL && ctx->sd->driver->open != NULL) {
            xrootd_sd_obj_t *o;
            int              sderr = 0;

            o = ctx->sd->driver->open(ctx->sd, path,
                                      xrootd_vfs_to_sd_flags(flags), 0644,
                                      &sderr);
            if (o == NULL) {
                if (err_out != NULL) {
                    *err_out = sderr;
                }
                errno = sderr;
                return NULL;
            }
            fd = o->fd;
        } else {
            fd = xrootd_open_beneath(ctx->rootfd, path, oflags, 0644);
        }
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

    if (xrootd_vfs_adopt_fd(ctx, path, fd, 0,
                            (flags & XROOTD_VFS_O_WRITE) ? 1u : 0u, &fh)
        != NGX_OK)
    {
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
    if (fh == NULL || fh->obj.driver == NULL
        || fh->obj.fd == NGX_INVALID_FILE)
    {
        return NGX_OK;
    }

    /* Release the descriptor through the backend's close slot; the driver
     * marks obj.fd invalid. The VFS keeps the error-log wrapper. */
    if (fh->obj.driver->close(&fh->obj) != NGX_OK) {
        XROOTD_DIAG_ERR(log != NULL ? log : fh->log, ngx_errno,
            "xrootd[disk]: close failed for \"%s\"",
            "a deferred write error surfaced at close — typically the "
            "filesystem filled up (ENOSPC) or the device returned an I/O error",
            "check free space and dmesg for disk errors; the file may be "
            "incomplete, so the client's write should be treated as failed",
            fh->path != NULL ? fh->path : "-");
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_fd_t
xrootd_vfs_file_fd(const xrootd_vfs_file_t *fh)
{
    return fh != NULL ? fh->obj.fd : NGX_INVALID_FILE;
}

void
xrootd_vfs_file_sd_obj(const xrootd_vfs_file_t *fh, xrootd_sd_obj_t *out)
{
    xrootd_vfs_handle_sd_obj(fh, out);
}

/* Read up to `len` bytes at `off` through the handle's storage driver — the
 * backend-neutral read used to serve a backend that exposes no single sendfile
 * fd (e.g. an object backend whose bytes span multiple block files). Returns the
 * bytes read (0 = EOF), or -1 with errno. One driver pread; the caller loops. */
ssize_t
xrootd_vfs_file_pread(xrootd_vfs_file_t *fh, void *buf, size_t len, off_t off)
{
    if (fh == NULL || fh->obj.driver == NULL
        || fh->obj.driver->pread == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    return fh->obj.driver->pread(&fh->obj, buf, len, off);
}

/* The fd only when the backend elects to back a zero-copy transfer of the whole
 * object, else NGX_INVALID_FILE. The decision is delegated to the backend's
 * read_sendfile_fd slot (want_zerocopy=1: the HTTP serve helper applies the
 * TLS/cleartext choice itself). The contract gate for callers that build a
 * sendfile / file-backed response. */
ngx_fd_t
xrootd_vfs_file_sendfile_fd(const xrootd_vfs_file_t *fh)
{
    if (fh == NULL) {
        return NGX_INVALID_FILE;
    }
    return xrootd_vfs_handle_sendfile_fd(fh, 0, (size_t) fh->size, 1);
}

/* Predicate form: 1 iff the backend will provide a sendfile fd for this handle. */
ngx_uint_t
xrootd_vfs_file_can_sendfile(const xrootd_vfs_file_t *fh)
{
    return xrootd_vfs_file_sendfile_fd(fh) != NGX_INVALID_FILE ? 1 : 0;
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
    xrootd_sd_stat_t st;
    xrootd_sd_obj_t  obj;

    if (fh == NULL || stat_out == NULL
        || (fh->obj.fd == NGX_INVALID_FILE && fh->obj.driver == NULL))
    {
        /* A driver-backed handle (object/remote backend) has no kernel fd; it
         * answers from cached metadata or the driver's fstat slot below. */
        errno = EINVAL;
        return NGX_ERROR;
    }

    /*
     * phase-45 W2/R1: when the metadata cached at adopt time is authoritative,
     * answer from it and skip a redundant fstat(2).  This is the common read
     * path (S3/WebDAV GET open the fd then immediately stat it).  stat_current is
     * set by adopt_fd only for read-only handles, whose file cannot change
     * through them; a writable handle has it clear and always takes a live fstat.
     */
    if (fh->stat_current) {
        ngx_memzero(stat_out, sizeof(*stat_out));
        stat_out->size = fh->size;
        stat_out->mtime = fh->mtime;
        stat_out->ctime = fh->ctime;
        stat_out->mode = (ngx_uint_t) fh->mode;
        stat_out->ino = fh->ino;
        stat_out->is_directory = S_ISDIR(fh->mode) ? 1 : 0;
        stat_out->is_regular = S_ISREG(fh->mode) ? 1 : 0;
        return NGX_OK;
    }

    /* Live re-stat through the backend's fstat slot (not a direct fstat(2)). */
    xrootd_vfs_handle_sd_obj(fh, &obj);
    if (obj.driver->fstat == NULL || obj.driver->fstat(&obj, &st) != NGX_OK) {
        return NGX_ERROR;
    }

    xrootd_vfs_sd_stat_to_vfs(&st, stat_out);
    return NGX_OK;
}
