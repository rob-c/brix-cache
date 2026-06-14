/*
 * slice.c — shared slice enumeration, path generation, and meta helpers.
 *
 * Phase 26 Step A.  Pure path/range arithmetic plus thin wrappers over the
 * existing cache meta and readiness helpers.  No origin I/O and no protocol
 * state lives here, so this library is identical for the HTTP and stream planes
 * and is unit-testable in isolation.
 */

#include "slice.h"
#include "cache_http.h"   /* xrootd_cache_file_ready */
#include "meta.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <glob.h>


ngx_int_t
xrootd_slice_path(const char *cache_path, size_t slice_size,
    ngx_uint_t slice_idx, char *out, size_t outsz)
{
    int n;

    if (cache_path == NULL || out == NULL || slice_size == 0) {
        return NGX_ERROR;
    }

    n = snprintf(out, outsz, "%s%s%zuk_%u",
                 cache_path, XROOTD_SLICE_INFIX,
                 slice_size / 1024, (unsigned) slice_idx);
    if (n < 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


ngx_int_t
xrootd_slice_enumerate(const char *cache_path, off_t file_size,
    size_t slice_size, off_t req_start, off_t req_end,
    xrootd_slice_t *out, ngx_uint_t max_out, ngx_uint_t *nout)
{
    ngx_uint_t  first_idx, last_idx, i, n, span;
    off_t       fs_start, fs_end;

    if (cache_path == NULL || out == NULL || nout == NULL
        || slice_size == 0 || req_start < 0 || req_end <= req_start)
    {
        return NGX_ERROR;
    }

    /* Clamp the requested range to the known file size. */
    if (file_size > 0 && req_end > file_size) {
        req_end = file_size;
    }
    if (req_end <= req_start) {
        return NGX_ERROR;
    }

    first_idx = (ngx_uint_t) (req_start / (off_t) slice_size);
    last_idx  = (ngx_uint_t) ((req_end - 1) / (off_t) slice_size);

    /* Reject requests that span more slices than the caller's buffer holds. */
    span = last_idx - first_idx + 1;
    if (span > max_out) {
        return NGX_DECLINED;
    }

    n = 0;
    for (i = first_idx; i <= last_idx; i++) {

        fs_start = (off_t) i * (off_t) slice_size;
        fs_end   = fs_start + (off_t) slice_size;
        if (file_size > 0 && fs_end > file_size) {
            fs_end = file_size;
        }

        out[n].file_start = fs_start;
        out[n].file_end   = fs_end;
        out[n].req_start  = (req_start > fs_start) ? req_start : fs_start;
        out[n].req_end    = (req_end   < fs_end)   ? req_end   : fs_end;
        out[n].idx        = i;

        if (xrootd_slice_path(cache_path, slice_size, i,
                              out[n].path, sizeof(out[n].path)) != NGX_OK)
        {
            return NGX_ERROR;
        }

        out[n].ready = xrootd_cache_file_ready(out[n].path);
        n++;
    }

    *nout = n;
    return (n > 0) ? NGX_OK : NGX_ERROR;
}


ngx_int_t
xrootd_slice_meta_base(const char *cache_path, char *out, size_t outsz)
{
    int n;

    n = snprintf(out, outsz, "%s%s", cache_path, XROOTD_SLICE_META_BASE_SUFFIX);
    if (n < 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


ngx_int_t
xrootd_slice_meta_validate(const char *cache_path, off_t origin_size,
    const char *origin_etag, ngx_log_t *log)
{
    char                 base[PATH_MAX];
    xrootd_cache_meta_t  meta;

    if (xrootd_slice_meta_base(cache_path, base, sizeof(base)) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * No usable meta yet (first fill, or unreadable) -> "unknown": the caller
     * proceeds and writes a fresh meta.  Only a meta that exists AND disagrees
     * triggers eviction, so a transient read error never causes data loss.
     */
    if (xrootd_cache_meta_read(log, base, &meta) != NGX_OK) {
        return NGX_OK;
    }

    if (origin_size > 0 && meta.size != (uint64_t) origin_size) {
        return NGX_DECLINED;
    }

    if (origin_etag != NULL && origin_etag[0] != '\0' && meta.etag_len > 0) {
        if (ngx_strcmp(meta.etag, origin_etag) != 0) {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


ngx_int_t
xrootd_slice_meta_write(const char *cache_path, off_t origin_size,
    const char *origin_etag, uint64_t mtime, ngx_log_t *log)
{
    char                 base[PATH_MAX];
    xrootd_cache_meta_t  meta;
    size_t               etag_len;

    if (xrootd_slice_meta_base(cache_path, base, sizeof(base)) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&meta, sizeof(meta));
    meta.mtime = mtime;
    meta.size  = (uint64_t) (origin_size > 0 ? origin_size : 0);

    if (origin_etag != NULL && origin_etag[0] != '\0') {
        etag_len = ngx_strlen(origin_etag);
        if (etag_len >= sizeof(meta.etag)) {
            etag_len = sizeof(meta.etag) - 1;
        }
        ngx_memcpy(meta.etag, origin_etag, etag_len);
        meta.etag[etag_len] = '\0';
        meta.etag_len = (uint8_t) etag_len;
    }

    return xrootd_cache_meta_write(log, base, &meta);
}


ngx_uint_t
xrootd_slice_evict_all(const char *cache_path, ngx_log_t *log)
{
    char        pattern[PATH_MAX];
    char        base[PATH_MAX];
    glob_t      g;
    ngx_uint_t  removed = 0;
    size_t      i;
    int         n;

    n = snprintf(pattern, sizeof(pattern), "%s%s",
                 cache_path, XROOTD_SLICE_GLOB_SUFFIX);
    if (n < 0 || (size_t) n >= sizeof(pattern)) {
        return 0;
    }

    /*
     * GLOB_NOSORT: ordering is irrelevant for deletion.  The pattern
     * "<cache_path>.__xrds_*" matches every per-slice file and its
     * .part/.lock siblings, but NOT the "<cache_path>.__xrds.meta" sidecar
     * (no '_' after "xrds"), which is removed explicitly below.
     */
    ngx_memzero(&g, sizeof(g));
    if (glob(pattern, GLOB_NOSORT, NULL, &g) == 0) {
        for (i = 0; i < g.gl_pathc; i++) {
            if (unlink(g.gl_pathv[i]) == 0) {
                removed++;
            }
        }
    }
    globfree(&g);

    /* The meta sidecar lives at "<cache_path>.__xrds.meta". */
    if (xrootd_slice_meta_base(cache_path, base, sizeof(base)) == NGX_OK) {
        char metapath[PATH_MAX];
        if (xrootd_cache_meta_path(metapath, sizeof(metapath), base) == 0
            && unlink(metapath) == 0)
        {
            removed++;
        }
    }

    if (removed > 0 && log != NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd cache: evicted %ui slice file(s) for \"%s\"",
                      removed, cache_path);
    }

    return removed;
}
