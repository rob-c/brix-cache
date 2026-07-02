/*
 * vfs_internal.h — implementation-private definitions shared by the vfs_*.c units.
 *
 * WHAT: Defines the real handle structs hidden behind vfs.h's opaque typedefs
 *       (xrootd_vfs_file_s, xrootd_vfs_dir_s), the inline confinement/write
 *       guards (xrootd_vfs_require_confined, xrootd_vfs_require_write), the
 *       ctx-path accessor (xrootd_vfs_ctx_path), the metrics/access-log observer
 *       helpers (xrootd_vfs_observe_ctx_op / xrootd_vfs_observe_file_op and the
 *       elapsed-usec/proto helpers they use), and the cross-unit prototypes
 *       (fill_stat, copy_path, adopt_fd, pread_full, pwrite_full).
 *
 * WHY:  Every vfs_*.c file needs the same guard-then-syscall-then-observe
 *       pattern and the same handle layout. Centralising it here keeps the
 *       per-op files thin and guarantees that confinement re-verification and
 *       metric/log emission happen identically for every operation.
 *
 * HOW:  The guards reject any ctx whose resolved path is empty or not confined
 *       (and, for writes, when allow_write is unset), setting errno. The
 *       observer helpers translate an rc/errno into an xrootd_err_class_t,
 *       compute latency from a start ngx_current_msec, then call
 *       xrootd_metric_op_done + xrootd_access_log_emit and restore errno so the
 *       caller can return it untouched. Only this header is included by the
 *       vfs_*.c units; protocol handlers include vfs.h instead.
 */
#ifndef XROOTD_VFS_INTERNAL_H
#define XROOTD_VFS_INTERNAL_H

#include "vfs.h"

#include "core/compat/crc32c.h"
#include "core/compat/namespace_ops.h"
#include "core/compat/staged_file.h"
#include "observability/metrics/access_log.h"
#include "fs/path/path.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct xrootd_vfs_file_s {
    /* Backend object: carries the open descriptor plus its driver + instance,
     * so close and (future) data-plane ops route through the storage driver
     * rather than assuming a raw POSIX fd. obj.fd is the descriptor for fd-based
     * backends, NGX_INVALID_FILE otherwise. */
    xrootd_sd_obj_t   obj;
    off_t             size;
    time_t            mtime;
    time_t            ctime;
    ino_t             ino;
    mode_t            mode;
    ngx_pool_t       *pool;
    ngx_log_t        *log;
    xrootd_vfs_ctx_t *ctx;
    char             *path;
    unsigned          from_cache:1;
    unsigned          is_tls:1;
    unsigned          cleanup_registered:1;
    /* phase-45 W2/R1: when set, the cached size/mtime/ctime/mode/ino above are
     * authoritative, so xrootd_vfs_file_stat() answers from them without a second
     * fstat.  adopt_fd sets it iff the handle is READ-ONLY: a read-only handle
     * cannot change its own file, so the open-time fstat stays valid for its
     * lifetime (this is the S3/WebDAV GET read-then-stat fast path).  A writable
     * handle leaves it 0, forcing a live fstat — correct even though no current
     * caller writes through a VFS handle (writes use the io_core job interface on
     * the raw fd), so a future write-through-handle path is safe by construction. */
    unsigned          stat_current:1;
};

struct xrootd_vfs_dir_s {
    DIR        *dir;
    ngx_pool_t *pool;
    ngx_log_t  *log;
    char       *path;
    const char *root_canon;   /* for broker-routed per-child lstat (impersonation) */
    /* Non-POSIX backend: the driver's open directory + the bits readdir needs to
     * stat children through the same driver. sd_dir != NULL selects the driver
     * path; `dir` stays NULL. */
    xrootd_sd_dir_t          *sd_dir;
    xrootd_sd_instance_t     *sd;
    const xrootd_sd_driver_t *drv;
    const char               *sd_logical;   /* export-relative dir path */
};

struct xrootd_vfs_staged_s {
    xrootd_staged_file_t  staged;   /* the compat temp-file primitive (POSIX)    */
    /* Non-NULL when the export selects a non-POSIX backend: the staged lifecycle
     * is delegated to that driver's staged_open/write/commit/abort slots and
     * `staged.fd` stays NGX_INVALID_FILE (object backends expose no kernel fd).
     * driver_total accumulates the bytes written, for the commit metric. */
    xrootd_sd_staged_t   *driver_staged;
    off_t                 driver_total;
    /* Write-back staging is no longer a vfs_staged mode: the registry composes the
     * sd_stage decorator (phase-63 C-2/C-6), so a remote-backend export with staging
     * enabled stages locally + promotes inside the driver's staged_* slots above. */
    xrootd_vfs_ctx_t     *ctx;      /* carries root_canon + final (resolved) path */
    ngx_pool_t           *pool;
    ngx_log_t            *log;
};

/* The export-root-relative ("logical") form of a confined path — what an
 * inst-keyed storage-driver op expects (the SD seam keys its namespace on the
 * logical path). Strips a root_canon prefix; returns `path` unchanged when it is
 * not under root_canon. Defined in vfs_open.c, shared with vfs_staged.c. */
const char *xrootd_vfs_export_relative(const xrootd_vfs_ctx_t *ctx,
    const char *path);
/* Path-based form for ctx-less callers (rename_path/mkdir_path). */
const char *xrootd_vfs_export_relative_root(const char *path,
    const char *root_canon);

/* The NON-default storage driver bound to this ctx (e.g. pblock), or NULL when
 * the export uses the default POSIX path. The VFS namespace + data ops dispatch
 * through it (with xrootd_vfs_export_relative paths) when non-NULL; otherwise they
 * fall to the existing POSIX confined-canon / ns_* helpers unchanged. */
static ngx_inline const xrootd_sd_driver_t *
xrootd_vfs_ctx_driver(const xrootd_vfs_ctx_t *ctx)
{
    if (ctx != NULL && ctx->sd != NULL
        && ctx->sd->driver != xrootd_sd_default_driver())
    {
        return ctx->sd->driver;
    }
    return NULL;
}

/* Map a storage-driver stat into the VFS stat callers see (the driver path's
 * counterpart of xrootd_vfs_fill_stat for a struct stat). */
static ngx_inline void
xrootd_vfs_sd_stat_fill(const xrootd_sd_stat_t *in, xrootd_vfs_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size = in->size;
    out->mtime = in->mtime;
    out->ctime = in->ctime;
    out->mode = (ngx_uint_t) in->mode;
    out->ino = in->ino;
    out->is_directory = in->is_dir ? 1 : 0;
    out->is_regular = in->is_reg ? 1 : 0;
}

/* Build a transient storage-driver object view from a ctx + fd: the bound
 * instance (or NULL for the default backend), that backend's driver, and the
 * fd. Used to ask the backend to perform/decide a per-fd operation without the
 * VFS hard-coding any concrete driver. "No explicit backend" resolves to
 * xrootd_sd_default_driver() rather than naming POSIX. */
static ngx_inline void
xrootd_vfs_ctx_sd_obj(const xrootd_vfs_ctx_t *ctx, ngx_fd_t fd,
    xrootd_sd_obj_t *obj)
{
    ngx_memzero(obj, sizeof(*obj));
    obj->inst = ctx != NULL ? ctx->sd : NULL;
    obj->driver = (obj->inst != NULL) ? obj->inst->driver
                                      : xrootd_sd_default_driver();
    obj->fd = fd;
}

/* Same, for an open handle: copy its backend object (driver + instance + fd). */
static ngx_inline void
xrootd_vfs_handle_sd_obj(const xrootd_vfs_file_t *fh, xrootd_sd_obj_t *obj)
{
    if (fh != NULL) {
        *obj = fh->obj;
    } else {
        xrootd_vfs_ctx_sd_obj(NULL, NGX_INVALID_FILE, obj);
    }
}

/* Map the backend's protocol-neutral stat into the VFS stat the callers see. */
static ngx_inline void
xrootd_vfs_sd_stat_to_vfs(const xrootd_sd_stat_t *in, xrootd_vfs_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size = in->size;
    out->mtime = in->mtime;
    out->ctime = in->ctime;
    out->mode = (ngx_uint_t) in->mode;
    out->ino = in->ino;
    out->is_directory = in->is_dir ? 1 : 0;
    out->is_regular = in->is_reg ? 1 : 0;
}

/* Ask the handle's backend for a sendfile-able fd over [off, off+len), passing
 * the VFS's storage-neutral zero-copy verdict; returns the fd, or
 * NGX_INVALID_FILE when the backend declines (or has no read_sendfile_fd slot).
 * This is the single place the VFS consults the backend's sendfile decision. */
static ngx_inline ngx_fd_t
xrootd_vfs_handle_sendfile_fd(const xrootd_vfs_file_t *fh, off_t off,
    size_t len, unsigned want_zerocopy)
{
    xrootd_sd_obj_t obj;

    xrootd_vfs_handle_sd_obj(fh, &obj);
    if (obj.driver == NULL || obj.driver->read_sendfile_fd == NULL) {
        return NGX_INVALID_FILE;
    }
    return obj.driver->read_sendfile_fd(&obj, off, len, want_zerocopy);
}

/* Borrow the ctx's resolved confined path as a NUL-terminated C string.
 * Returns NULL (not "") when ctx or the resolved path is unset; the pointer
 * is owned by the ctx and must not be freed or outlive it. */
static ngx_inline const char *
xrootd_vfs_ctx_path(const xrootd_vfs_ctx_t *ctx)
{
    if (ctx == NULL || ctx->resolved.resolved.data == NULL) {
        return NULL;
    }

    return (const char *) ctx->resolved.resolved.data;
}

/* Read guard: assert the ctx has a non-empty, kernel-confined resolved path.
 * Returns NGX_OK if confined, else NGX_ERROR with errno=EINVAL. Every wire op
 * must pass this before touching the filesystem. */
static ngx_inline ngx_int_t
xrootd_vfs_require_confined(const xrootd_vfs_ctx_t *ctx)
{
    const char *path = xrootd_vfs_ctx_path(ctx);

    if (ctx == NULL || path == NULL || path[0] == '\0'
        || !ctx->resolved.is_confined)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Write guard: confinement check (as above) plus ctx->allow_write.
 * Returns NGX_OK only when both hold; otherwise NGX_ERROR with errno=EINVAL
 * (unconfined) or EACCES (write not permitted). */
static ngx_inline ngx_int_t
xrootd_vfs_require_write(const xrootd_vfs_ctx_t *ctx)
{
    if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!ctx->allow_write) {
        errno = EACCES;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Translate a namespace status into a faithful POSIX errno. The namespace layer
 * sets res.sys_errno for syscall failures but leaves it 0 for the conditions it
 * derives itself (notably XROOTD_NS_NOT_EMPTY from its own emptiness probe), so
 * callers that collapse a failed xrootd_ns_* result to errno must use this for
 * the sys_errno==0 case rather than a blanket EIO — otherwise a non-empty rmdir
 * surfaces as EIO/500 instead of ENOTEMPTY/409. */
static ngx_inline int
xrootd_vfs_ns_status_errno(xrootd_ns_status_t status)
{
    switch (status) {
    case XROOTD_NS_OK:        return 0;
    case XROOTD_NS_NOT_FOUND: return ENOENT;
    case XROOTD_NS_DENIED:    return EACCES;
    case XROOTD_NS_EXISTS:    return EEXIST;
    case XROOTD_NS_CONFLICT:  return ENOTDIR;
    case XROOTD_NS_NOT_EMPTY: return ENOTEMPTY;
    case XROOTD_NS_TOO_LONG:  return ENAMETOOLONG;
    case XROOTD_NS_NO_SPACE:  return ENOSPC;
    case XROOTD_NS_IO_ERROR:  return EIO;
    }

    return EIO;
}

/* Pick the protocol label for this ctx's metrics, defaulting to
 * XROOTD_PROTO_STREAM when ctx is NULL or its metrics_proto is out of range. */
static ngx_inline xrootd_proto_t
xrootd_vfs_metrics_proto(const xrootd_vfs_ctx_t *ctx)
{
    if (ctx == NULL || ctx->metrics_proto >= XROOTD_PROTO_COUNT) {
        return XROOTD_PROTO_STREAM;
    }

    return ctx->metrics_proto;
}

/* phase-56 D-1: a real monotonic timestamp in NANOseconds for op-latency.
 * Replaces the cached ngx_current_msec, which (a) only advances on event-loop
 * ticks — so a synchronous metadata op that never yields reported 0 µs — and
 * (b) is millisecond-resolution, quantizing the whole sub-ms band to 0/1000 µs.
 * CLOCK_MONOTONIC is vDSO-backed (~20 ns/call, lost in the syscalls the op
 * already makes) and gives honest sub-µs deltas. NOT CLOCK_MONOTONIC_COARSE —
 * that is also ~1-4 ms granularity and would only fix (a), not the resolution. */
static ngx_inline uint64_t
xrootd_vfs_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

/* Latency since start_ns in MICROseconds (start is an xrootd_vfs_now_ns()
 * snapshot). Clamps to 0 if the monotonic clock appears to have gone backwards. */
static ngx_inline ngx_msec_t
xrootd_vfs_elapsed_usec(uint64_t start_ns)
{
    uint64_t now_ns = xrootd_vfs_now_ns();

    if (now_ns < start_ns) {
        return 0;
    }

    return (ngx_msec_t) ((now_ns - start_ns) / 1000ull);
}

/* Post-op observer: derive the error class from rc/sys_errno, compute latency
 * from start_msec, then emit one metric (xrootd_metric_op_done) and one access
 * log line (xrootd_access_log_emit) for op. bytes is the transferred count;
 * result may be NULL. Borrows path (does not copy). Restores errno=sys_errno on
 * return so the caller can propagate it unchanged. */
static ngx_inline void
xrootd_vfs_observe_ctx_op(const xrootd_vfs_ctx_t *ctx, const char *path,
    xrootd_metric_op_t op, const xrootd_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns)
{
    xrootd_err_class_t err;
    ngx_msec_t         latency_usec;

    err = rc == NGX_OK ? XROOTD_ERR_NONE
                       : xrootd_metric_err_from_errno(sys_errno);
    latency_usec = xrootd_vfs_elapsed_usec(start_ns);

    xrootd_metric_op_done(xrootd_vfs_metrics_proto(ctx), op, bytes,
                          latency_usec, err);
    xrootd_access_log_emit(ctx, path, op, result, bytes, err, latency_usec);

    errno = sys_errno;
}

/* Handle-keyed convenience wrapper for xrootd_vfs_observe_ctx_op: pulls ctx and
 * path from fh (tolerating fh==NULL). Same errno-restoring semantics. */
static ngx_inline void
xrootd_vfs_observe_file_op(const xrootd_vfs_file_t *fh,
    xrootd_metric_op_t op, const xrootd_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns)
{
    xrootd_vfs_observe_ctx_op(fh != NULL ? fh->ctx : NULL,
                              fh != NULL ? fh->path : NULL,
                              op, result, bytes, rc, sys_errno, start_ns);
}

/* Translate a struct stat into the protocol-neutral xrootd_vfs_stat_t: zeroes
 * *out first, then copies size/mtime/ctime/mode/ino and sets is_directory /
 * is_regular from the mode. Silent no-op if either pointer is NULL. */
void xrootd_vfs_fill_stat(const struct stat *st, xrootd_vfs_stat_t *out);

/* Duplicate a NUL-terminated C string into pool (ngx_pnalloc'd, NUL-terminated).
 * Returns the copy, or NULL with errno=EINVAL (bad args) / ENOMEM. The copy
 * lives as long as pool. */
char *xrootd_vfs_copy_path(ngx_pool_t *pool, const char *path);

/* Wrap an already-open fd in a freshly pcalloc'd handle (from ctx->pool):
 * fstat()s fd to populate cached size/mtime/ino/mode, dups path, and records
 * from_cache and ctx->is_tls. `writable` is non-zero iff the fd was opened for
 * writing; it gates the stat_current fast path (see xrootd_vfs_file_stat) — a
 * writable handle never trusts its open-time metadata, a read-only one always
 * can (the file cannot change through it). On success *out is set and the handle
 * adopts fd (caller stops owning it). Returns NGX_ERROR (out unchanged/NULL) on
 * bad args (EINVAL), fstat failure (errno from fstat), or OOM (ENOMEM). */
ngx_int_t xrootd_vfs_adopt_fd(xrootd_vfs_ctx_t *ctx, const char *path,
    ngx_fd_t fd, unsigned from_cache, unsigned writable,
    xrootd_vfs_file_t **out);

/* xrootd_vfs_pread_full / xrootd_vfs_pwrite_full are now declared in the public
 * vfs.h (raw fd full read/write primitives) so module byte loops outside src/fs
 * can route through the storage seam too. */

#endif /* XROOTD_VFS_INTERNAL_H */
