/*
 * vfs_internal.h — implementation-private definitions shared by the vfs_*.c units.
 *
 * WHAT: Defines the real handle structs hidden behind vfs.h's opaque typedefs
 *       (xrootd_vfs_file_s, xrootd_vfs_dir_s), the inline confinement/write
 *       guards (xrootd_vfs_require_confined, xrootd_vfs_require_write), the
 *       ctx-path accessor (xrootd_vfs_ctx_path), the metrics/access-log observer
 *       helpers (xrootd_vfs_observe_ctx_op / xrootd_vfs_observe_file_op and the
 *       elapsed-usec/proto helpers they use), and the cross-unit prototypes
 *       (fill_stat, copy_path, register_fd_cleanup, adopt_fd, pread_full,
 *       pwrite_full). Also defines XROOTD_VFS_COPY_CHUNK.
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

#include "../compat/crc32c.h"
#include "../compat/namespace_ops.h"
#include "../metrics/access_log.h"
#include "../path/path.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define XROOTD_VFS_COPY_CHUNK 65536

struct xrootd_vfs_file_s {
    ngx_fd_t          fd;
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
    /* phase-45 W2/R1: the cached size/mtime/ctime/mode/ino above are current
     * (set by adopt_fd's fstat, no write since), so xrootd_vfs_file_stat() can
     * answer from them without a second fstat.  Cleared by xrootd_vfs_write(). */
    unsigned          stat_current:1;
};

struct xrootd_vfs_dir_s {
    DIR        *dir;
    ngx_pool_t *pool;
    ngx_log_t  *log;
    char       *path;
    const char *root_canon;   /* for broker-routed per-child lstat (impersonation) */
};

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

/* Latency since start_msec in MICROseconds (start is an ngx_current_msec
 * snapshot). Clamps to 0 if the cached clock appears to have gone backwards. */
static ngx_inline ngx_msec_t
xrootd_vfs_elapsed_usec(ngx_msec_t start_msec)
{
    ngx_msec_t now;

    now = ngx_current_msec;
    if (now < start_msec) {
        return 0;
    }

    return (now - start_msec) * 1000;
}

/* Post-op observer: derive the error class from rc/sys_errno, compute latency
 * from start_msec, then emit one metric (xrootd_metric_op_done) and one access
 * log line (xrootd_access_log_emit) for op. bytes is the transferred count;
 * result may be NULL. Borrows path (does not copy). Restores errno=sys_errno on
 * return so the caller can propagate it unchanged. */
static ngx_inline void
xrootd_vfs_observe_ctx_op(const xrootd_vfs_ctx_t *ctx, const char *path,
    xrootd_metric_op_t op, const xrootd_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, ngx_msec_t start_msec)
{
    xrootd_err_class_t err;
    ngx_msec_t         latency_usec;

    err = rc == NGX_OK ? XROOTD_ERR_NONE
                       : xrootd_metric_err_from_errno(sys_errno);
    latency_usec = xrootd_vfs_elapsed_usec(start_msec);

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
    size_t bytes, ngx_int_t rc, int sys_errno, ngx_msec_t start_msec)
{
    xrootd_vfs_observe_ctx_op(fh != NULL ? fh->ctx : NULL,
                              fh != NULL ? fh->path : NULL,
                              op, result, bytes, rc, sys_errno, start_msec);
}

/* Translate a struct stat into the protocol-neutral xrootd_vfs_stat_t: zeroes
 * *out first, then copies size/mtime/ctime/mode/ino and sets is_directory /
 * is_regular from the mode. Silent no-op if either pointer is NULL. */
void xrootd_vfs_fill_stat(const struct stat *st, xrootd_vfs_stat_t *out);

/* Duplicate a NUL-terminated C string into pool (ngx_pnalloc'd, NUL-terminated).
 * Returns the copy, or NULL with errno=EINVAL (bad args) / ENOMEM. The copy
 * lives as long as pool. */
char *xrootd_vfs_copy_path(ngx_pool_t *pool, const char *path);

/* Arm a pool cleanup that closes fd when pool is destroyed (the standard way to
 * hand a dup'd fd to a sendfile buffer without leaking). path is borrowed for
 * the cleanup's log name; pass NULL for a default. Returns NGX_OK, or NGX_ERROR
 * with errno=EINVAL (bad fd/pool) / ENOMEM. Does NOT take fd ownership until the
 * cleanup actually fires. */
ngx_int_t xrootd_vfs_register_fd_cleanup(ngx_pool_t *pool, ngx_fd_t fd,
    const char *path, ngx_log_t *log);

/* Wrap an already-open fd in a freshly pcalloc'd handle (from ctx->pool):
 * fstat()s fd to populate cached size/mtime/ino/mode, dups path, and records
 * from_cache and ctx->is_tls. On success *out is set and the handle adopts fd
 * (caller stops owning it). Returns NGX_ERROR (out unchanged/NULL) on bad args
 * (EINVAL), fstat failure (errno from fstat), or OOM (ENOMEM). */
ngx_int_t xrootd_vfs_adopt_fd(xrootd_vfs_ctx_t *ctx, const char *path,
    ngx_fd_t fd, unsigned from_cache, xrootd_vfs_file_t **out);

/* EINTR-safe, short-read-tolerant pread of up to len bytes at offset into buf.
 * Loops until len is filled or EOF. *nread (optional) always receives the byte
 * count, even on error. Returns NGX_OK on full read or clean EOF; NGX_ERROR on
 * a real pread error (errno set), with *nread holding the partial count. */
ngx_int_t xrootd_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len,
    off_t offset, size_t *nread);

/* EINTR-safe, short-write-safe pwrite of exactly len bytes at offset from buf.
 * Returns NGX_OK only when all len bytes are written; NGX_ERROR otherwise with
 * errno set (a 0-byte pwrite is reported as EIO). No partial-count is exposed. */
ngx_int_t xrootd_vfs_pwrite_full(ngx_fd_t fd, const u_char *buf, size_t len,
    off_t offset);

#endif /* XROOTD_VFS_INTERNAL_H */
