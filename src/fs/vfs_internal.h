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
};

struct xrootd_vfs_dir_s {
    DIR        *dir;
    ngx_pool_t *pool;
    ngx_log_t  *log;
    char       *path;
};

static ngx_inline const char *
xrootd_vfs_ctx_path(const xrootd_vfs_ctx_t *ctx)
{
    if (ctx == NULL || ctx->resolved.resolved.data == NULL) {
        return NULL;
    }

    return (const char *) ctx->resolved.resolved.data;
}

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

static ngx_inline xrootd_proto_t
xrootd_vfs_metrics_proto(const xrootd_vfs_ctx_t *ctx)
{
    if (ctx == NULL || ctx->metrics_proto >= XROOTD_PROTO_COUNT) {
        return XROOTD_PROTO_STREAM;
    }

    return ctx->metrics_proto;
}

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

static ngx_inline void
xrootd_vfs_observe_file_op(const xrootd_vfs_file_t *fh,
    xrootd_metric_op_t op, const xrootd_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, ngx_msec_t start_msec)
{
    xrootd_vfs_observe_ctx_op(fh != NULL ? fh->ctx : NULL,
                              fh != NULL ? fh->path : NULL,
                              op, result, bytes, rc, sys_errno, start_msec);
}

void xrootd_vfs_fill_stat(const struct stat *st, xrootd_vfs_stat_t *out);
char *xrootd_vfs_copy_path(ngx_pool_t *pool, const char *path);
ngx_int_t xrootd_vfs_register_fd_cleanup(ngx_pool_t *pool, ngx_fd_t fd,
    const char *path, ngx_log_t *log);
ngx_int_t xrootd_vfs_adopt_fd(xrootd_vfs_ctx_t *ctx, const char *path,
    ngx_fd_t fd, unsigned from_cache, xrootd_vfs_file_t **out);
ngx_int_t xrootd_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len,
    off_t offset, size_t *nread);
ngx_int_t xrootd_vfs_pwrite_full(ngx_fd_t fd, const u_char *buf, size_t len,
    off_t offset);

#endif /* XROOTD_VFS_INTERNAL_H */
