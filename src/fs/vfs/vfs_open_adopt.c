/*
 * vfs_open_adopt.c — VFS ctx priming, handle adoption, and shared path helpers.
 *
 * WHAT: Hosts the handle-construction half of the VFS open unit:
 *       brix_vfs_ctx_init() (prime a per-request ctx), brix_vfs_fill_stat()
 *       (struct stat -> brix_vfs_stat_t), brix_vfs_copy_path() (pool-dup a C
 *       string), brix_vfs_adopt_fd()/brix_vfs_adopt_obj() (wrap an already-open
 *       fd / a backend object in a brix_vfs_file_t), and
 *       brix_vfs_export_relative()/_root() (export-root-relative path form).
 *
 * WHY:  These are the pieces the open orchestrator (vfs_open.c) and the cache
 *       layer both build handles with. Splitting them out of vfs_open.c keeps
 *       both files under the size cap while leaving the open cascade in one place.
 *       Every symbol here is already public (declared in vfs_internal.h / vfs.h)
 *       because external units (the cache layer, vfs_staged.c) also call them —
 *       so nothing new crosses a boundary; this is purely a file-size split.
 *
 * HOW:  brix_vfs_adopt_fd()/_obj() capture open-time metadata through the
 *       backend's fstat slot (never a direct fstat(2)) into a freshly pcalloc'd
 *       handle, dup the path, and record from_cache/is_tls/stat_current.
 *       brix_vfs_export_relative_root() strips an absolute export root from a
 *       confined path so an inst-keyed storage driver keys its namespace on the
 *       logical path. See vfs_open.c for the open cascade that consumes these.
 */
#include "vfs_internal.h"
#include "vfs_backend_registry.h"

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
