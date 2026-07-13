/*
 * vfs_open.c — VFS open/close, handle lifecycle, and shared file helpers.
 *
 * WHAT: Implements brix_vfs_open()/brix_vfs_close() and the brix_vfs_file_*
 *       accessors (fd/path/size/mtime/from_cache/file_stat). Also hosts the
 *       cross-unit helpers declared in vfs_internal.h: brix_vfs_fill_stat()
 *       (struct stat -> brix_vfs_stat_t), brix_vfs_copy_path() (pool-dup a
 *       C string) and brix_vfs_adopt_fd() (wrap an already-open fd in a
 *       handle).
 *
 * WHY:  Open is the one place that has to reconcile three concerns at once:
 *       write permission, the read-through cache, and kernel-enforced
 *       confinement. Concentrating that decision here keeps every other op file
 *       able to assume a valid, confined, already-fstat'd handle.
 *
 * HOW:  brix_vfs_open() re-verifies confinement, gates writes on
 *       ctx->allow_write, optionally pre-creates the parent dir tree
 *       (BRIX_VFS_O_MKDIRPATH), then tries brix_cache_open() first. On a
 *       cache miss it translates flags via brix_vfs_open_flags() and walks the
 *       confinement cascade strongest-first: persistent rootfd +
 *       brix_open_beneath (openat2 RESOLVE_BENEATH), else root_canon +
 *       brix_open_confined_canon, else a raw open() reachable only for
 *       server-constructed paths with no export root. The resulting fd is
 *       wrapped by brix_vfs_adopt_fd(), which fstat()s it into the handle.
 */
#include "vfs_internal.h"
#include "vfs_backend_registry.h"
#include <sys/mman.h>   /* memfd_create (phase-71 step 2 memfd sendfile proxy) */
#include "fs/cache/open.h"
#include "fs/path/beneath.h"
#include "core/compat/log_diag.h"

/* Populate a per-request brix_vfs_ctx_t with the fields the HTTP front ends
 * (WebDAV, S3) set identically: a transient (rootfd = -1) confined open of an
 * already-resolved canonical path. Zeroes the ctx first, then fills pool/log,
 * the metrics proto, the export + cache roots (deriving cache_enabled), the
 * write gate, the TLS flag, the identity, and the resolved path (is_confined).
 * Callers may still adjust individual fields afterwards (e.g. cache_writethrough
 * config). Kept HTTP-agnostic on purpose so the header stays stream-includable —
 * callers pass pool/log/is_tls extracted from their own request object. */
void
brix_vfs_ctx_init(brix_vfs_ctx_t *vctx, ngx_pool_t *pool, ngx_log_t *log,
    brix_proto_t proto, const char *root_canon, const char *cache_root_canon,
    int allow_write, int is_tls, brix_identity_t *identity,
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
    vctx->sd = brix_vfs_backend_resolve(root_canon, log);
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

/* Copy a struct stat into the protocol-neutral brix_vfs_stat_t (zeroes the
 * output first; sets is_directory/is_regular from the mode). No-op on NULL. */
void
brix_vfs_fill_stat(const struct stat *st, brix_vfs_stat_t *out)
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
brix_vfs_copy_path(ngx_pool_t *pool, const char *path)
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

/* Wrap an already-open fd in a freshly pcalloc'd brix_vfs_file_t: fstat the
 * fd into the cached metadata, dup the path, and record attrs.from_cache/is_tls.
 * attrs.writable gates the stat_current fast path (set only for read-only
 * handles). Used by both brix_vfs_open() and the cache layer's open path. */
ngx_int_t
brix_vfs_adopt_fd(brix_vfs_ctx_t *ctx, const char *path, ngx_fd_t fd,
    brix_vfs_adopt_attrs_t attrs, brix_vfs_file_t **out)
{
    brix_sd_stat_t    st;
    brix_sd_obj_t     obj;
    brix_vfs_file_t  *fh;

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
    brix_vfs_ctx_sd_obj(ctx, fd, &obj);
    if (obj.driver->fstat == NULL || obj.driver->fstat(&obj, &st) != NGX_OK) {
        return NGX_ERROR;
    }

    fh = ngx_pcalloc(ctx->pool, sizeof(*fh));
    if (fh == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    fh->path = brix_vfs_copy_path(ctx->pool, path);
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
    fh->from_cache = attrs.from_cache ? 1 : 0;
    fh->is_tls = ctx->is_tls;
    /* Trust the open-time metadata for stat() only on a read-only handle: the
     * file cannot change through it, so the fstat above stays authoritative for
     * the handle's lifetime. A writable handle leaves this 0 so brix_vfs_file_stat()
     * always issues a live fstat (its bytes/mtime/size move as it is written). */
    fh->stat_current = attrs.writable ? 0 : 1;
    fh->memfd = NGX_INVALID_FILE;

    *out = fh;
    return NGX_OK;
}

/* brix_vfs_adopt_obj — build a handle from an object the backend's open slot
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
brix_vfs_adopt_obj(brix_vfs_ctx_t *ctx, const char *path,
    brix_sd_obj_t *o, unsigned writable, brix_vfs_file_t **out);

/* brix_vfs_export_relative — the export-root-relative ("logical") form of a
 * confined path, which is what an inst-keyed storage-driver op expects (per the
 * SD seam contract). Some callers (WebDAV/S3) resolve to an absolute path under
 * root_canon; strip that prefix so a non-POSIX backend keys its namespace on the
 * logical path. Returns `path` unchanged when it is not under root_canon.
 * Declared in vfs_internal.h; shared with vfs_staged.c. */
/* Path-based form: strip `root_canon` (an absolute export root) from `path`. */
const char *
brix_vfs_export_relative_root(const char *path, const char *root_canon)
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
brix_vfs_export_relative(const brix_vfs_ctx_t *ctx, const char *path)
{
    return brix_vfs_export_relative_root(path, ctx->root_canon);
}

ngx_int_t
brix_vfs_adopt_obj(brix_vfs_ctx_t *ctx, const char *path,
    brix_sd_obj_t *o, unsigned writable, brix_vfs_file_t **out)
{
    brix_sd_stat_t   st;
    brix_vfs_file_t *fh;

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
    fh->path = brix_vfs_copy_path(ctx->pool, path);
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
    fh->memfd = NGX_INVALID_FILE;

    *out = fh;
    return NGX_OK;
}

static int
brix_vfs_open_flags(ngx_uint_t flags)
{
    int oflags;

    if ((flags & BRIX_VFS_O_READ) && (flags & BRIX_VFS_O_WRITE)) {
        oflags = O_RDWR;
    } else if (flags & BRIX_VFS_O_WRITE) {
        oflags = O_WRONLY;
    } else {
        oflags = O_RDONLY;
    }

    if (flags & BRIX_VFS_O_CREATE) {
        oflags |= O_CREAT;
    }
    if (flags & BRIX_VFS_O_EXCL) {
        oflags |= O_EXCL;
    }
    if (flags & BRIX_VFS_O_TRUNC) {
        oflags |= O_TRUNC;
    }
    if (flags & BRIX_VFS_O_APPEND) {
        oflags |= O_APPEND;
    }

    return oflags;
}

/* Map the VFS open flags to the backend-neutral SD open flags the driver open
 * slot consumes (the driver maps them to O_* itself). 1:1 with the O_* mapping
 * above, so a driver-routed open is byte-identical to the legacy beneath open. */
static int
brix_vfs_to_sd_flags(ngx_uint_t flags)
{
    int sd = 0;

    if (flags & BRIX_VFS_O_READ)   { sd |= BRIX_SD_O_READ; }
    if (flags & BRIX_VFS_O_WRITE)  { sd |= BRIX_SD_O_WRITE; }
    if (flags & BRIX_VFS_O_CREATE) { sd |= BRIX_SD_O_CREATE; }
    if (flags & BRIX_VFS_O_EXCL)   { sd |= BRIX_SD_O_EXCL; }
    if (flags & BRIX_VFS_O_TRUNC)  { sd |= BRIX_SD_O_TRUNC; }
    if (flags & BRIX_VFS_O_APPEND) { sd |= BRIX_SD_O_APPEND; }

    return sd;
}

/* For BRIX_VFS_O_MKDIRPATH: create the target's parent directory chain
 * (mode 0755) before the file open is attempted. A driver-backed export gets
 * the chain in the DRIVER's namespace (brix_vfs_backend_mkpath — for e.g.
 * pblock the catalog IS the namespace; raw host mkdirs would leave the new
 * file an orphan no readdir can reach); the default posix export keeps the
 * confined host mkdir. */
static ngx_int_t
brix_vfs_mkdir_parent_path(brix_vfs_ctx_t *ctx, const char *path)
{
    char       *parent;
    char       *slash;
    ngx_int_t   rc;

    if (ctx->root_canon == NULL || path == NULL) {
        return NGX_OK;
    }

    parent = brix_vfs_copy_path(ctx->pool, path);
    if (parent == NULL) {
        return NGX_ERROR;
    }

    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return NGX_OK;
    }

    *slash = '\0';

    rc = brix_vfs_backend_mkpath(ctx->root_canon,
             brix_vfs_export_relative_root(parent, ctx->root_canon),
             0755, ctx->log);
    if (rc != NGX_DECLINED) {
        return (rc == 0) ? NGX_OK : NGX_ERROR;
    }

    if (brix_mkdir_recursive_confined_canon(ctx->log, ctx->root_canon,
                                              parent, 0755, NULL) != 0)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* brix_vfs_open_set_err — record the current (or supplied) errno into the
 * optional *err_out out-param.
 *
 * WHAT: Copy `err` into *err_out when the caller passed one.
 * WHY:  brix_vfs_open() threads a syscall errno back to the caller through an
 *       optional pointer at a dozen return sites; centralising the NULL-guard
 *       keeps each early-return to a single line and removes the repeated
 *       `if (err_out != NULL) *err_out = ...;` boilerplate.
 * HOW:  Pure store behind a NULL check; no other side effects. */
static void
brix_vfs_open_set_err(int *err_out, int err)
{
    if (err_out != NULL) {
        *err_out = err;
    }
}

/* brix_vfs_open_precheck — enforce the invariants every open must satisfy
 * before any storage is touched: confinement, the global write gate, and the
 * optional parent-dir pre-create.
 *
 * WHAT: Re-verify ctx confinement, deny a write open unless ctx->allow_write,
 *       and (for BRIX_VFS_O_MKDIRPATH) build the target's parent dir chain.
 * WHY:  These three gates are policy, not storage: they run identically for the
 *       driver and POSIX paths, so hoisting them keeps the orchestrator flat and
 *       keeps the confinement/write-gate decision in exactly one place.
 * HOW:  Early-return NGX_ERROR with errno set on the first failing gate (errno
 *       from require_confined / mkdir; EACCES for the write gate). NGX_OK ⇒ the
 *       caller may proceed to open `path`. */
static ngx_int_t
brix_vfs_open_precheck(brix_vfs_ctx_t *ctx, ngx_uint_t flags, const char *path)
{
    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    if ((flags & BRIX_VFS_O_WRITE) && !ctx->allow_write) {
        errno = EACCES;
        return NGX_ERROR;
    }

    if ((flags & BRIX_VFS_O_MKDIRPATH)
        && brix_vfs_mkdir_parent_path(ctx, path) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* brix_vfs_open_try_cache — consult the read-through cache and account the
 * hit/miss metric.
 *
 * WHAT: Call brix_cache_open(); on a hit build *fh and count a cache hit; on a
 *       hard error propagate it; on a plain miss count the miss (only for a
 *       cacheable read) and signal the caller to fall through to a real open.
 * WHY:  Isolates the cache decision + its metric bookkeeping from the open
 *       cascade so the orchestrator reads as one linear step.
 * HOW:  Returns NGX_OK (hit, *fh set), NGX_ERROR (cache error, errno set), or
 *       NGX_DECLINED (miss — caller opens the backing store). No behaviour
 *       change: same brix_metric_cache_result() calls in the same order. */
static ngx_int_t
brix_vfs_open_try_cache(brix_vfs_ctx_t *ctx, ngx_uint_t flags,
    brix_vfs_file_t **fh)
{
    ngx_int_t rc;

    rc = brix_cache_open(ctx, flags, fh);
    if (rc == NGX_OK) {
        brix_metric_cache_result(brix_vfs_metrics_proto(ctx), 1, 0);
        return NGX_OK;
    }
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (ctx->cache_enabled && !(flags & BRIX_VFS_O_WRITE)
        && !(flags & BRIX_VFS_O_NOCACHE))
    {
        brix_metric_cache_result(brix_vfs_metrics_proto(ctx), 0, 0);
    }

    return NGX_DECLINED;
}

/* brix_vfs_open_via_driver — open through a non-POSIX storage backend's own
 * namespace and adopt the object it returns.
 *
 * WHAT: For a non-default driver with an open slot, resolve the per-user cred,
 *       call the driver open on the export-relative path, and wrap the returned
 *       object (preserving its per-open state) in a handle.
 * WHY:  A non-POSIX backend (e.g. pblock) owns its own confinement and returns
 *       an object the POSIX fd cascade cannot interpret; it must therefore run
 *       BEFORE that cascade, and adopting the object (not a bare fd) keeps the
 *       backend's per-open state alive. Encapsulating it here keeps the POSIX
 *       cascade untouched.
 * HOW:  Returns NGX_OK with *fh set on success; NGX_DECLINED (leaving *fh) when
 *       this ctx is not driver-routed so the caller runs the POSIX cascade;
 *       NGX_ERROR with errno + *err_out set on driver/adopt failure (the driver
 *       object is closed and any heap shell freed before returning). */
static ngx_int_t
brix_vfs_open_via_driver(brix_vfs_ctx_t *ctx, ngx_uint_t flags,
    const char *path, int *err_out, brix_vfs_file_t **fh)
{
    brix_sd_obj_t   *o;
    int              sderr = 0;
    brix_sd_ucred_t  ustore;
    brix_sd_cred_t   ucred;
    int              use_cred = 0;

    if (ctx->sd == NULL || ctx->sd->driver == brix_sd_default_driver()
        || ctx->sd->driver->open == NULL)
    {
        return NGX_DECLINED;
    }

    ngx_memzero(&ucred, sizeof(ucred));
    if (brix_vfs_backend_cred(ctx, &ustore, &ucred, &use_cred, err_out)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    o = brix_sd_open_maybe_cred(ctx->sd,
                                brix_vfs_export_relative(ctx, path),
                                brix_vfs_to_sd_flags(flags), 0644,
                                use_cred ? &ucred : NULL, &sderr);
    if (o == NULL) {
        brix_vfs_open_set_err(err_out, sderr);
        errno = sderr;
        return NGX_ERROR;
    }

    if (brix_vfs_adopt_obj(ctx, path, o,
            (flags & BRIX_VFS_O_WRITE) ? 1u : 0u, fh) != NGX_OK)
    {
        int err = errno;

        o->driver->close(o);
        if (o->heap_shell) {
            free(o);
        }
        brix_vfs_open_set_err(err_out, err);
        errno = err;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* brix_vfs_open_confined_fd — open a bare POSIX fd for `path` under the
 * confinement cascade, strongest first.
 *
 * WHAT: Return an open fd (or NGX_INVALID_FILE with errno) for the default-POSIX
 *       export using the strongest available confinement mechanism.
 * WHY:  This is the security seam: the openat2(RESOLVE_BENEATH) confinement must
 *       stay in exactly ONE place so an outward symlink can never be followed
 *       out of the export. Splitting it out keeps that guarantee auditable.
 * HOW:  Cascade, strongest first —
 *         1. ctx->rootfd >= 0  → the borrowed-instance POSIX driver open (which
 *            does openat2 RESOLVE_BENEATH), else brix_open_beneath() directly.
 *         2. root_canon only   → brix_open_confined_canon() (same RESOLVE_BENEATH
 *            semantics, rootfd opened per call).
 *         3. neither            → raw open(): NOT a bypass — reached only for a
 *            server-constructed absolute path in a non-export ctx (no root at
 *            all); a client request always sets a root and takes branch 1 or 2.
 *       The O_* set for the raw/beneath branches is derived from `flags` here;
 *       driver-routed opens re-derive SD flags. errno is the syscall's own on a
 *       failed open. */
static ngx_fd_t
brix_vfs_open_confined_fd(brix_vfs_ctx_t *ctx, ngx_uint_t flags,
    const char *path, int *err_out)
{
    int oflags = brix_vfs_open_flags(flags);

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
            ctx->sd = brix_sd_posix_borrow_instance(ctx->pool, ctx->log,
                                                      ctx->rootfd,
                                                      ctx->root_canon);
        }
        if (ctx->sd != NULL && ctx->sd->driver->open != NULL) {
            brix_sd_obj_t *o;
            int            sderr = 0;

            o = ctx->sd->driver->open(ctx->sd, path,
                                      brix_vfs_to_sd_flags(flags), 0644,
                                      &sderr);
            if (o == NULL) {
                brix_vfs_open_set_err(err_out, sderr);
                errno = sderr;
                return NGX_INVALID_FILE;
            }
            return o->fd;
        }
        return brix_open_beneath(ctx->rootfd, path, oflags, 0644);
    }

    if (ctx->root_canon != NULL) {
        return brix_open_confined_canon(ctx->log, ctx->root_canon, path,
                                        oflags, 0644);
    }

    return open(path, oflags, 0644);
}

/* brix_vfs_open_via_posix — the default-POSIX open path: obtain a confined fd
 * then wrap it in a handle.
 *
 * WHAT: Open `path` through brix_vfs_open_confined_fd() and adopt the resulting
 *       fd into *fh, closing it on an adopt failure.
 * WHY:  Pairs the confinement cascade with the single handle-build path so the
 *       orchestrator's POSIX branch is one call, and fd ownership on failure is
 *       handled in one place.
 * HOW:  Returns NGX_OK with *fh set, or NGX_ERROR with errno + *err_out set. */
static ngx_int_t
brix_vfs_open_via_posix(brix_vfs_ctx_t *ctx, ngx_uint_t flags,
    const char *path, int *err_out, brix_vfs_file_t **fh)
{
    ngx_fd_t                fd;
    brix_vfs_adopt_attrs_t  attrs;

    fd = brix_vfs_open_confined_fd(ctx, flags, path, err_out);
    if (fd == NGX_INVALID_FILE) {
        brix_vfs_open_set_err(err_out, errno);
        return NGX_ERROR;
    }

    attrs.from_cache = 0;
    attrs.writable   = (flags & BRIX_VFS_O_WRITE) ? 1u : 0u;
    if (brix_vfs_adopt_fd(ctx, path, fd, attrs, fh) != NGX_OK) {
        int err = errno;

        ngx_close_file(fd);
        brix_vfs_open_set_err(err_out, err);
        errno = err;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Open the resolved ctx path under the confinement cascade. Returns a handle
 * or NULL with the syscall errno in *err_out. Cache hits short-circuit; writes
 * require ctx->allow_write. See the file header for the full open sequence.
 *
 * Orchestrator: a flat sequence of named steps — precheck (confinement + write
 * gate + mkdir), cache, then either the non-POSIX driver open or the POSIX
 * confinement cascade. Each step reports NGX_OK / NGX_ERROR / NGX_DECLINED. */
brix_vfs_file_t *
brix_vfs_open(brix_vfs_ctx_t *ctx, ngx_uint_t flags, int *err_out)
{
    const char       *path;
    brix_vfs_file_t  *fh = NULL;
    ngx_int_t         rc;

    brix_vfs_open_set_err(err_out, 0);

    path = brix_vfs_ctx_path(ctx);
    if (brix_vfs_open_precheck(ctx, flags, path) != NGX_OK) {
        brix_vfs_open_set_err(err_out, errno);
        return NULL;
    }

    rc = brix_vfs_open_try_cache(ctx, flags, &fh);
    if (rc == NGX_OK) {
        return fh;
    }
    if (rc == NGX_ERROR) {
        brix_vfs_open_set_err(err_out, errno);
        return NULL;
    }

    /*
     * A non-POSIX storage backend (e.g. pblock) owns its own namespace and
     * confinement, so route EVERY open through its driver and adopt the returned
     * object (carrying its per-open state). This runs before the POSIX cascade:
     * that cascade opens a bare POSIX fd this backend's fstat/read slots cannot
     * interpret. POSIX (default driver, or unset backend) declines and falls
     * through to the cascade unchanged.
     */
    rc = brix_vfs_open_via_driver(ctx, flags, path, err_out, &fh);
    if (rc == NGX_OK) {
        return fh;
    }
    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (brix_vfs_open_via_posix(ctx, flags, path, err_out, &fh) != NGX_OK) {
        return NULL;
    }

    return fh;
}

ngx_int_t
brix_vfs_close(brix_vfs_file_t *fh, ngx_log_t *log)
{
    if (fh == NULL) {
        return NGX_OK;
    }

    /* phase-71 step 2: release a materialised memfd sendfile proxy, if any. This
     * runs before the fd-based early-out below because a CAP_MEMFILE backend has
     * obj.fd == NGX_INVALID_FILE yet may still own a memfd. */
    if (fh->memfd != NGX_INVALID_FILE) {
        (void) ngx_close_file(fh->memfd);
        fh->memfd = NGX_INVALID_FILE;
    }

    if (fh->obj.driver == NULL || fh->obj.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    /* Release the descriptor through the backend's close slot; the driver
     * marks obj.fd invalid. The VFS keeps the error-log wrapper. */
    if (fh->obj.driver->close(&fh->obj) != NGX_OK) {
        BRIX_DIAG_ERR(log != NULL ? log : fh->log, ngx_errno,
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
brix_vfs_file_fd(const brix_vfs_file_t *fh)
{
    return fh != NULL ? fh->obj.fd : NGX_INVALID_FILE;
}

void
brix_vfs_file_sd_obj(const brix_vfs_file_t *fh, brix_sd_obj_t *out)
{
    brix_vfs_handle_sd_obj(fh, out);
}

/* Read up to `len` bytes at `off` through the handle's storage driver — the
 * backend-neutral read used to serve a backend that exposes no single sendfile
 * fd (e.g. an object backend whose bytes span multiple block files). Returns the
 * bytes read (0 = EOF), or -1 with errno. One driver pread; the caller loops. */
ssize_t
brix_vfs_file_pread(brix_vfs_file_t *fh, void *buf, size_t len, off_t off)
{
    if (fh == NULL || fh->obj.driver == NULL
        || fh->obj.driver->pread == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    return fh->obj.driver->pread(&fh->obj, buf, len, off);
}

/* brix_vfs_memfile_materialize — phase-71 step 2 memfd sendfile proxy.
 *
 * WHAT: For a CAP_MEMFILE backend that exposes no kernel fd (obj.fd invalid,
 *       read_sendfile_fd declines), pread the whole object into an anonymous
 *       memfd ONCE and cache it on fh->memfd, so the VFS can hand every backend
 *       a uniform seekable fd for the sendfile / file-backed serve path.
 * WHY:  Removes the last backend-identity branch in the serve path: callers stop
 *       special-casing "no fd → build a memory buffer myself" and use one fd path.
 * HOW:  memfd_create + a pread→write loop through the driver's worker-safe pread
 *       slot; the fd is owned by the handle and closed in brix_vfs_close. Returns
 *       the cached fd on repeat calls. NGX_INVALID_FILE on any failure (the caller
 *       then falls back to its legacy memory-backed path — no behaviour change). */
static ngx_fd_t
brix_vfs_memfile_materialize(brix_vfs_file_t *fh)
{
    brix_sd_obj_t obj;
    ngx_fd_t      fd;
    off_t         off;
    u_char        buf[65536];

    if (fh->memfd != NGX_INVALID_FILE) {
        return fh->memfd;              /* already materialised */
    }

    brix_vfs_handle_sd_obj(fh, &obj);
    if (obj.driver == NULL || obj.driver->pread == NULL
        || !(brix_sd_caps(obj.inst) & BRIX_SD_CAP_MEMFILE))
    {
        return NGX_INVALID_FILE;
    }

    fd = (ngx_fd_t) memfd_create("brix-vfs-memfile", MFD_CLOEXEC);
    if (fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }

    for (off = 0; off < fh->size; /* advanced below */) {
        size_t  want = (size_t) ngx_min((off_t) sizeof(buf), fh->size - off);
        ssize_t n = obj.driver->pread(&obj, buf, want, off);

        if (n <= 0) {
            (void) ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }
        if (write(fd, buf, (size_t) n) != n) {
            (void) ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }
        off += n;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
        (void) ngx_close_file(fd);
        return NGX_INVALID_FILE;
    }

    fh->memfd = fd;
    return fd;
}

/* The fd only when the backend elects to back a zero-copy transfer of the whole
 * object, else NGX_INVALID_FILE. The decision is delegated to the backend's
 * read_sendfile_fd slot (want_zerocopy=1: the HTTP serve helper applies the
 * TLS/cleartext choice itself). For a fd-less CAP_MEMFILE backend the VFS
 * materialises a handle-owned memfd (phase-71 step 2) so the serve path is a
 * uniform seekable fd for every backend. The contract gate for callers that
 * build a sendfile / file-backed response. */
ngx_fd_t
brix_vfs_file_sendfile_fd(const brix_vfs_file_t *fh)
{
    ngx_fd_t fd;

    if (fh == NULL) {
        return NGX_INVALID_FILE;
    }
    fd = brix_vfs_handle_sendfile_fd(fh, 0, (size_t) fh->size, 1);
    if (fd != NGX_INVALID_FILE) {
        return fd;
    }
    /* fh is const by contract, but the memfd cache is an internal materialisation
     * that does not change the observable file — safe to fill lazily here. */
    return brix_vfs_memfile_materialize((brix_vfs_file_t *) fh);
}

/* Predicate form: 1 iff the backend will provide a sendfile fd for this handle. */
ngx_uint_t
brix_vfs_file_can_sendfile(const brix_vfs_file_t *fh)
{
    return brix_vfs_file_sendfile_fd(fh) != NGX_INVALID_FILE ? 1 : 0;
}

/* The census name of the backend serving this handle: the bound instance's
 * driver name, or "posix" for the default instance / a NULL handle. Used for
 * per-backend byte attribution at serve time (the serve paths release the
 * handle before the bytes are counted, so callers capture this up front). */
const char *
brix_vfs_file_backend_name(const brix_vfs_file_t *fh)
{
    if (fh == NULL || fh->ctx == NULL || fh->ctx->sd == NULL) {
        return "posix";
    }
    return brix_sd_backend_name(fh->ctx->sd);
}

const char *
brix_vfs_file_path(const brix_vfs_file_t *fh)
{
    return (fh != NULL && fh->path != NULL) ? fh->path : "";
}

off_t
brix_vfs_file_size(const brix_vfs_file_t *fh)
{
    return fh != NULL ? fh->size : 0;
}

time_t
brix_vfs_file_mtime(const brix_vfs_file_t *fh)
{
    return fh != NULL ? fh->mtime : 0;
}

ngx_uint_t
brix_vfs_file_from_cache(const brix_vfs_file_t *fh)
{
    return (fh != NULL && fh->from_cache) ? 1 : 0;
}

ngx_int_t
brix_vfs_file_stat(const brix_vfs_file_t *fh, brix_vfs_stat_t *stat_out)
{
    brix_sd_stat_t st;
    brix_sd_obj_t  obj;

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
    brix_vfs_handle_sd_obj(fh, &obj);
    if (obj.driver->fstat == NULL || obj.driver->fstat(&obj, &st) != NGX_OK) {
        return NGX_ERROR;
    }

    brix_vfs_sd_stat_to_vfs(&st, stat_out);
    return NGX_OK;
}
