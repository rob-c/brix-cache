/*
 * vfs_open.c — the VFS open orchestrator and its confinement cascade.
 *
 * WHAT: Implements brix_vfs_open() and its private steps — the flag mappers,
 *       the parent-dir pre-create, the precheck (confinement + write gate), the
 *       read-through cache probe, the non-POSIX driver-open path, and the POSIX
 *       confinement cascade. The handle-construction helpers it calls
 *       (brix_vfs_adopt_fd/_obj, brix_vfs_copy_path, brix_vfs_export_relative)
 *       live in vfs_open_adopt.c; close + the brix_vfs_file_* accessors live in
 *       vfs_open_handle.c. All three are declared in vfs_internal.h / vfs.h.
 *
 * WHY:  Open is the one place that has to reconcile three concerns at once:
 *       write permission, the read-through cache, and kernel-enforced
 *       confinement. Concentrating that decision here keeps every other op file
 *       able to assume a valid, confined, already-fstat'd handle. This file was
 *       split from the handle/accessor helpers only for the file-size cap; the
 *       security seam (the confinement cascade) is unchanged.
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
#include "fs/cache/open.h"
#include "fs/path/beneath.h"

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
