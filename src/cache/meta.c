#include "meta.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

/*
 * meta.c — read/write of the per-cache-file metadata sidecar.
 *
 * WHAT: Persists and loads the xrootd_cache_meta_t record (origin mtime, size,
 *       and optional etag) that accompanies each cached file. The sidecar path
 *       is derived from the cache file path by xrootd_cache_meta_path() (see
 *       paths.c).
 *
 * WHY:  A cached copy is only valid while it still matches the origin. The
 *       sidecar lets open.c (xrootd_cache_validate_meta) detect a stale entry
 *       by comparing the recorded size/mtime against the live origin stat, so
 *       changed-at-origin files are not served from cache.
 *
 * HOW:  The record is a fixed-size struct written and read verbatim as raw
 *       bytes through xrootd_cache_meta_rw_all(), a short-read/short-write-safe
 *       loop. Files are opened with O_NOFOLLOW|O_CLOEXEC (and O_NOCTTY); writes
 *       use O_CREAT|O_TRUNC and zero-pad the unused etag tail for a stable
 *       on-disk image. xrootd_cache_meta_from_stat() builds an in-memory record
 *       from a struct stat plus an optional etag, clamping the etag to
 *       XROOTD_CACHE_META_ETAG_MAX. NGX_DECLINED distinguishes "no/short/invalid
 *       meta" (treat as cache miss) from NGX_ERROR (real I/O failure).
 */

/*
 * xrootd_cache_meta_rw_all — read or write exactly len bytes on fd.
 *
 * Loops over write(2) (write_op != 0) or read(2) until the whole buffer is
 * transferred, retrying on EINTR. Returns NGX_OK on full transfer, NGX_DECLINED
 * on premature EOF (read returning 0, i.e. a truncated meta file), or NGX_ERROR
 * on any other failure.
 */
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

/*
 * xrootd_cache_meta_from_stat — populate a meta record from a stat + etag.
 *
 * Zeroes *meta, then copies st->st_mtime and st->st_size and, if etag is
 * non-empty, up to XROOTD_CACHE_META_ETAG_MAX bytes of it. Returns NGX_ERROR
 * (EINVAL) on NULL arguments, otherwise NGX_OK.
 */
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

/*
 * xrootd_cache_meta_read — load the sidecar meta for cache_path into *meta.
 *
 * Derives the sidecar path, opens it O_RDONLY|O_NOFOLLOW, and reads the full
 * fixed-size record. Returns NGX_OK on success; NGX_DECLINED when no sidecar
 * exists (ENOENT), the file is truncated, or etag_len is out of range (treat as
 * cache miss); NGX_ERROR on any other I/O error.
 */
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

    /* §9: zero first so a legacy-sized sidecar leaves the versioned tail at zero
     * (version 0). Read the mandatory legacy base, then best-effort read the tail —
     * a short tail read (old sidecar) is fine and keeps version 0. */
    ngx_memzero(meta, sizeof(*meta));
    rc = xrootd_cache_meta_rw_all(fd, meta, XROOTD_CACHE_META_BASE_SIZE, 0);
    if (rc == NGX_OK) {
        u_char   *tail = (u_char *) meta + XROOTD_CACHE_META_BASE_SIZE;
        size_t    taillen = sizeof(*meta) - XROOTD_CACHE_META_BASE_SIZE;
        ngx_int_t trc = xrootd_cache_meta_rw_all(fd, tail, taillen, 0);
        if (trc == NGX_ERROR) {
            rc = NGX_ERROR;
        } else if (trc == NGX_DECLINED) {
            ngx_memzero(tail, taillen);   /* legacy sidecar: no versioned tail */
        }
    }
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

/*
 * xrootd_cache_meta_touch — §9 record a cache hit (read-modify-write the stats).
 */
ngx_int_t
xrootd_cache_meta_touch(ngx_log_t *log, const char *cache_path, uint64_t nbytes)
{
    xrootd_cache_meta_t meta;
    ngx_int_t           rc;

    rc = xrootd_cache_meta_read(log, cache_path, &meta);
    if (rc != NGX_OK) {
        return rc;   /* no/invalid sidecar → nothing to touch */
    }
    meta.version       = XROOTD_CACHE_META_VERSION;
    meta.access_count += 1;
    meta.bytes_served += nbytes;
    meta.last_access   = (uint64_t) ngx_time();
    return xrootd_cache_meta_write(log, cache_path, &meta);
}

/*
 * xrootd_cache_meta_write — persist *meta to the sidecar for cache_path.
 *
 * Validates etag_len, then writes a local copy with the unused etag tail
 * zero-padded (stable on-disk image) to the sidecar opened
 * O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW (mode 0644). Returns NGX_OK on a full
 * write, NGX_ERROR on bad arguments or any I/O failure.
 */
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
