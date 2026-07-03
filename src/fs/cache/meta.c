#include "meta.h"
#include "cinfo.h"                   /* BRIX_CACHE_DIRTY_BLOCK granule */
#include "fs/meta/xmeta_path.h"      /* the shared raw-path record carrier */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

ngx_int_t
brix_cache_meta_from_stat(const struct stat *st, const char *etag,
    brix_cache_meta_t *meta)
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
        if (etag_len > BRIX_CACHE_META_ETAG_MAX) {
            etag_len = BRIX_CACHE_META_ETAG_MAX;
        }
        ngx_memcpy(meta->etag, etag, etag_len);
        meta->etag_len = (uint8_t) etag_len;
    }

    return NGX_OK;
}

/*
 * brix_cache_meta_read — load the sidecar meta for cache_path into *meta.
 *
 * Derives the sidecar path, opens it O_RDONLY|O_NOFOLLOW, and reads the full
 * fixed-size record. Returns NGX_OK on success; NGX_DECLINED when no sidecar
 * exists (ENOENT), the file is truncated, or etag_len is out of range (treat as
 * cache miss); NGX_ERROR on any other I/O error.
 */
/* Legacy fixed-size ".meta" sidecar reader (pre-xmeta-migration caches). The
 * on-disk layout is exactly the brix_cache_meta_t legacy base — origin mtime,
 * size, and a bounded etag — so a cache written before the unified metadata
 * record still validates. NGX_OK on a good record; NGX_DECLINED (cache miss)
 * when the sidecar is absent, truncated, or its etag length is out of range. */
static ngx_int_t
cache_meta_read_legacy(const char *cache_path, brix_cache_meta_t *meta)
{
    char    path[PATH_MAX];
    int     fd;
    ssize_t n;

    if (brix_cache_meta_path(path, sizeof(path), cache_path) != 0) {
        return NGX_DECLINED;
    }
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  /* vfs-seam-allow: server-managed cache-root sidecar, opened as worker */
    if (fd < 0) {
        return NGX_DECLINED;   /* ENOENT / no legacy sidecar -> cache miss */
    }
    ngx_memzero(meta, sizeof(*meta));
    n = read(fd, meta, BRIX_CACHE_META_BASE_SIZE);
    (void) close(fd);
    if (n != (ssize_t) BRIX_CACHE_META_BASE_SIZE
        || meta->etag_len > BRIX_CACHE_META_ETAG_MAX)
    {
        return NGX_DECLINED;   /* truncated / corrupt -> treat as miss */
    }
    meta->version = 0;         /* legacy base: no versioned tail */
    return NGX_OK;
}

ngx_int_t
brix_cache_meta_read(ngx_log_t *log, const char *cache_path,
    brix_cache_meta_t *meta)
{
    brix_xmeta_t xm;
    int            rc;

    (void) log;

    if (cache_path == NULL || meta == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    rc = brix_xmeta_path_load(cache_path, &xm);
    if (rc != BRIX_XMETA_OK) {
        /* No unified brix record (FOREIGN covers both "absent" and a foreign/
         * stock record): fall back to a legacy ".meta" sidecar so caches written
         * before the xmeta migration still validate. NGX_ERROR only on a genuine
         * I/O fault loading the unified record. */
        if (rc == BRIX_XMETA_FOREIGN) {
            return cache_meta_read_legacy(cache_path, meta);
        }
        return NGX_ERROR;
    }

    ngx_memzero(meta, sizeof(*meta));
    meta->mtime        = xm.origin_mtime;
    meta->size         = (uint64_t) xm.file_size;
    meta->version      = BRIX_CACHE_META_VERSION;
    meta->access_count = xm.access_cnt;
    meta->last_access  = (uint64_t) xm.astat.detach_time;
    meta->bytes_served = (uint64_t) xm.astat.bytes_hit;
    meta->etag_len = (xm.etag_len <= sizeof(meta->etag)) ? xm.etag_len : 0;
    ngx_memcpy(meta->etag, xm.etag, meta->etag_len);
    meta->cks_alg_len = (xm.cks_alg_len <= sizeof(meta->cks_alg))
                        ? xm.cks_alg_len : 0;
    ngx_memcpy(meta->cks_alg, xm.cks_alg, meta->cks_alg_len);
    meta->cks_len = (xm.cks_len < sizeof(meta->cks_hex)) ? xm.cks_len : 0;
    ngx_memcpy(meta->cks_hex, xm.cks_hex, meta->cks_len);
    meta->cks_hex[meta->cks_len] = 0;
    brix_xmeta_free(&xm);
    return NGX_OK;
}

/* Apply *meta's fields onto a loaded (or fresh) record, preserving whatever
 * the record already carries (bitmap, block CRCs, dirty state). */
static void
meta_onto_record(const brix_cache_meta_t *meta, brix_xmeta_t *xm)
{
    xm->origin_mtime = meta->mtime;
    xm->access_cnt   = meta->access_count;
    if (meta->last_access != 0 || meta->bytes_served != 0) {
        if (xm->astat_count == 0) {
            xm->astat_count = 1;
        }
        xm->astat.attach_time = (int64_t) meta->last_access;
        xm->astat.detach_time = (int64_t) meta->last_access;
        xm->astat.bytes_hit   = (int64_t) meta->bytes_served;
    }
    xm->etag_len = (meta->etag_len <= sizeof(xm->etag)) ? meta->etag_len : 0;
    ngx_memcpy(xm->etag, meta->etag, xm->etag_len);
    xm->cks_alg_len = (meta->cks_alg_len <= sizeof(xm->cks_alg))
                      ? meta->cks_alg_len : 0;
    ngx_memcpy(xm->cks_alg, meta->cks_alg, xm->cks_alg_len);
    xm->cks_len = (meta->cks_len <= sizeof(xm->cks_hex)) ? meta->cks_len : 0;
    ngx_memcpy(xm->cks_hex, meta->cks_hex, xm->cks_len);
}

/*
 * brix_cache_meta_touch — §9 record a cache hit (read-modify-write the stats).
 */
ngx_int_t
brix_cache_meta_touch(ngx_log_t *log, const char *cache_path, uint64_t nbytes)
{
    brix_xmeta_t xm;
    int            lockfd, rc;

    (void) log;

    if (cache_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    lockfd = brix_xmeta_path_lock(cache_path);
    if (lockfd < 0) {
        return NGX_ERROR;
    }
    rc = brix_xmeta_path_load(cache_path, &xm);
    if (rc != BRIX_XMETA_OK) {
        brix_xmeta_path_unlock(lockfd);
        return (rc == BRIX_XMETA_FOREIGN) ? NGX_DECLINED : NGX_ERROR;
    }

    xm.access_cnt += 1;
    if (xm.astat_count == 0) {
        xm.astat_count = 1;
        xm.astat.attach_time = (int64_t) time(NULL);
    }
    xm.astat.detach_time = (int64_t) time(NULL);
    xm.astat.bytes_hit  += (int64_t) nbytes;

    rc = (brix_xmeta_path_save(cache_path, &xm) == BRIX_XMETA_OK)
         ? NGX_OK : NGX_ERROR;
    brix_xmeta_free(&xm);
    brix_xmeta_path_unlock(lockfd);
    return rc;
}

/*
 * brix_cache_meta_write — persist *meta onto the unified record for
 * cache_path (creating it when absent; preserving bitmap/CRC/dirty state).
 */
ngx_int_t
brix_cache_meta_write(ngx_log_t *log, const char *cache_path,
    const brix_cache_meta_t *meta)
{
    brix_xmeta_t xm;
    int            lockfd, rc;

    (void) log;

    if (cache_path == NULL || meta == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    lockfd = brix_xmeta_path_lock(cache_path);
    if (lockfd < 0) {
        return NGX_ERROR;
    }
    rc = brix_xmeta_path_load(cache_path, &xm);
    if (rc == BRIX_XMETA_ERR
        || (rc == BRIX_XMETA_FOREIGN
            && brix_xmeta_init(&xm, (int64_t) meta->size,
                                 BRIX_CACHE_DIRTY_BLOCK)
               != BRIX_XMETA_OK))
    {
        brix_xmeta_path_unlock(lockfd);
        return NGX_ERROR;
    }
    if (rc == BRIX_XMETA_FOREIGN) {
        /* fresh record for a whole cached file: fully present */
        if (xm.nblocks > 0) {
            ngx_memset(xm.bitmap, 0xFF, (size_t) ((xm.nblocks + 7) / 8));
        }
        xm.have_blockcrc = 0;
    }
    meta_onto_record(meta, &xm);

    rc = (brix_xmeta_path_save(cache_path, &xm) == BRIX_XMETA_OK)
         ? NGX_OK : NGX_ERROR;
    brix_xmeta_free(&xm);
    brix_xmeta_path_unlock(lockfd);
    return rc;
}
