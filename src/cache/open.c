#include "open.h"
#include "cache_internal.h"
#include "meta.h"

#include "../fs/vfs_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

ngx_int_t
xrootd_cache_path_for_resolved(const char *cache_root_canon,
    const char *root_canon, const char *resolved, char *out, size_t outsz)
{
    size_t      cache_len;
    size_t      root_len;
    size_t      suffix_len;
    const char *suffix;

    if (cache_root_canon == NULL || root_canon == NULL || resolved == NULL
        || out == NULL || outsz == 0 || cache_root_canon[0] == '\0'
        || root_canon[0] == '\0' || resolved[0] == '\0')
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    root_len = strlen(root_canon);
    if (ngx_strncmp((u_char *) resolved, (u_char *) root_canon, root_len)
        != 0)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (root_len == 1 && root_canon[0] == '/') {
        suffix = (resolved[1] != '\0') ? resolved : "";
    } else {
        suffix = resolved + root_len;
    }
    if (suffix[0] != '\0' && suffix[0] != '/') {
        errno = EINVAL;
        return NGX_ERROR;
    }

    cache_len = strlen(cache_root_canon);
    suffix_len = strlen(suffix);
    if (cache_len == 1 && cache_root_canon[0] == '/' && suffix[0] == '/') {
        suffix++;
        suffix_len--;
    }
    if (cache_len + suffix_len >= outsz) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    ngx_memcpy(out, cache_root_canon, cache_len);
    ngx_memcpy(out + cache_len, suffix, suffix_len + 1);

    return NGX_OK;
}

static ngx_int_t
xrootd_cache_validate_meta(const char *cache_path, const struct stat *st,
    ngx_log_t *log)
{
    xrootd_cache_meta_t meta;

    if (xrootd_cache_meta_read(log, cache_path, &meta) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (meta.size != (uint64_t) st->st_size
        || meta.mtime != (uint64_t) st->st_mtime)
    {
        errno = ESTALE;
        return NGX_DECLINED;
    }

    return NGX_OK;
}

ngx_int_t
xrootd_cache_open(xrootd_vfs_ctx_t *ctx, ngx_uint_t flags,
    xrootd_vfs_file_t **fh_out)
{
    char        cache_path[PATH_MAX];
    const char *resolved;
    int         ready;
    ngx_fd_t    fd;
    struct stat st;
    ngx_int_t   rc;

    if (fh_out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    *fh_out = NULL;

    if (ctx == NULL || !ctx->cache_enabled
        || ctx->cache_root_canon == NULL || ctx->cache_root_canon[0] == '\0'
        || (flags & XROOTD_VFS_O_NOCACHE)
        || (flags & (XROOTD_VFS_O_WRITE | XROOTD_VFS_O_CREATE
                     | XROOTD_VFS_O_TRUNC | XROOTD_VFS_O_APPEND)))
    {
        return NGX_DECLINED;
    }

    resolved = xrootd_vfs_ctx_path(ctx);
    if (xrootd_cache_path_for_resolved(ctx->cache_root_canon,
                                       ctx->root_canon, resolved,
                                       cache_path, sizeof(cache_path))
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    ready = xrootd_cache_file_ready(cache_path);
    if (ready <= 0) {
        return NGX_DECLINED;
    }

    fd = open(cache_path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd == NGX_INVALID_FILE) {
        return (errno == ENOENT || errno == ENOTDIR) ? NGX_DECLINED
                                                     : NGX_ERROR;
    }

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int err = errno;
        ngx_close_file(fd);
        errno = err != 0 ? err : EINVAL;
        return NGX_ERROR;
    }

    if (xrootd_cache_validate_meta(cache_path, &st, ctx->log) != NGX_OK) {
        int err = errno;
        ngx_close_file(fd);
        errno = err;
        return NGX_DECLINED;
    }

    rc = xrootd_vfs_adopt_fd(ctx, cache_path, fd, 1, fh_out);
    if (rc != NGX_OK) {
        int err = errno;
        ngx_close_file(fd);
        errno = err;
    }

    return rc;
}

ngx_int_t
xrootd_cache_record_access(const char *cache_path, size_t bytes,
    ngx_log_t *log)
{
    (void) bytes;

    if (cache_path == NULL || cache_path[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }

#if defined(UTIME_OMIT)
    {
        struct timespec ts[2];

        ts[0].tv_sec = 0;
        ts[0].tv_nsec = UTIME_NOW;
        ts[1].tv_sec = 0;
        ts[1].tv_nsec = UTIME_OMIT;

        if (utimensat(AT_FDCWD, cache_path, ts, 0) != 0) {
            if (log != NULL) {
                ngx_log_error(NGX_LOG_DEBUG, log, errno,
                              "xrootd: cache access timestamp update failed \"%s\"",
                              cache_path);
            }
            return NGX_ERROR;
        }
    }
#else
    (void) log;
#endif

    return NGX_OK;
}
