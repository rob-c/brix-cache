#include "meta.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

static ngx_int_t
xrootd_cache_meta_rw_all(int fd, void *buf, size_t len, unsigned write_op)
{
    u_char *p;

    p = buf;
    while (len > 0) {
        ssize_t n;

        if (write_op) {
            n = write(fd, p, len);
        } else {
            n = read(fd, p, len);
        }

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NGX_ERROR;
        }

        if (n == 0) {
            return NGX_DECLINED;
        }

        p += (size_t) n;
        len -= (size_t) n;
    }

    return NGX_OK;
}

ngx_int_t
xrootd_cache_meta_from_stat(const struct stat *st, const char *etag,
    xrootd_cache_meta_t *meta)
{
    size_t etag_len;

    if (st == NULL || meta == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    ngx_memzero(meta, sizeof(*meta));
    meta->mtime = (uint64_t) st->st_mtime;
    meta->size = (uint64_t) st->st_size;

    if (etag != NULL && etag[0] != '\0') {
        etag_len = strlen(etag);
        if (etag_len > XROOTD_CACHE_META_ETAG_MAX) {
            etag_len = XROOTD_CACHE_META_ETAG_MAX;
        }
        ngx_memcpy(meta->etag, etag, etag_len);
        meta->etag_len = (uint8_t) etag_len;
    }

    return NGX_OK;
}

ngx_int_t
xrootd_cache_meta_read(ngx_log_t *log, const char *cache_path,
    xrootd_cache_meta_t *meta)
{
    char      meta_path[PATH_MAX];
    int       fd;
    ngx_int_t rc;

    (void) log;

    if (cache_path == NULL || meta == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (xrootd_cache_meta_path(meta_path, sizeof(meta_path), cache_path) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    fd = open(meta_path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return (errno == ENOENT) ? NGX_DECLINED : NGX_ERROR;
    }

    rc = xrootd_cache_meta_rw_all(fd, meta, sizeof(*meta), 0);
    if (close(fd) != 0 && rc == NGX_OK) {
        rc = NGX_ERROR;
    }

    if (rc != NGX_OK) {
        return rc;
    }

    if (meta->etag_len > XROOTD_CACHE_META_ETAG_MAX) {
        errno = EINVAL;
        return NGX_DECLINED;
    }

    return NGX_OK;
}

ngx_int_t
xrootd_cache_meta_write(ngx_log_t *log, const char *cache_path,
    const xrootd_cache_meta_t *meta)
{
    char             meta_path[PATH_MAX];
    int              fd;
    ngx_int_t        rc;
    xrootd_cache_meta_t disk_meta;

    (void) log;

    if (cache_path == NULL || meta == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (meta->etag_len > XROOTD_CACHE_META_ETAG_MAX) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (xrootd_cache_meta_path(meta_path, sizeof(meta_path), cache_path) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    disk_meta = *meta;
    if (disk_meta.etag_len < XROOTD_CACHE_META_ETAG_MAX) {
        ngx_memzero(disk_meta.etag + disk_meta.etag_len,
                    XROOTD_CACHE_META_ETAG_MAX - disk_meta.etag_len);
    }

    fd = open(meta_path,
              O_WRONLY | O_CREAT | O_TRUNC | O_NOCTTY | O_CLOEXEC
              | O_NOFOLLOW,
              0644);
    if (fd < 0) {
        return NGX_ERROR;
    }

    rc = xrootd_cache_meta_rw_all(fd, &disk_meta, sizeof(disk_meta), 1);
    if (close(fd) != 0 && rc == NGX_OK) {
        rc = NGX_ERROR;
    }

    return rc;
}
