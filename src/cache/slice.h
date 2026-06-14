#ifndef XROOTD_CACHE_SLICE_H
#define XROOTD_CACHE_SLICE_H

/*
 * slice.h — shared fixed-size slice enumeration and path generation.
 *
 * Phase 26.  Both the HTTP/WebDAV GET handler and the XRootD stream kXR_read
 * handler use this library so that the slice naming and range arithmetic exist
 * in exactly one place.  A file is cached as independent fixed-size slices:
 *
 *     <cache_path>.__xrds_<SLICE_KiB>k_<IDX>
 *
 * The slice size is encoded in the filename, so changing xrootd_cache_slice
 * automatically invalidates old slices (they have different names).  A
 * file-level meta sidecar (<cache_path>.__xrds.meta, reusing the cache meta
 * format) tracks the origin etag/size to detect mid-transfer file changes.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "meta.h"

/*
 * Cap the number of slices a single request may span.  16 slices at 128 MiB is
 * 2 GiB — larger than any single HEP kXR_read or HTTP range in practice.  A
 * request spanning more slices than this is rejected (416) by the callers.
 */
#define XROOTD_SLICE_MAX_PER_REQUEST  16

/* Filename infixes/suffixes for slice files and the file-level meta sidecar. */
#define XROOTD_SLICE_INFIX            ".__xrds_"
#define XROOTD_SLICE_META_BASE_SUFFIX ".__xrds"   /* meta sidecar gets ".meta" appended */
#define XROOTD_SLICE_GLOB_SUFFIX      ".__xrds_*"

/*
 * xrootd_slice_t — one slice covering part of a requested byte range.
 *
 * file_start / file_end: byte positions in the origin file (file_end exclusive).
 * req_start  / req_end:  intersection with the client's requested range (excl).
 * idx:                   0-based slice index.
 * path:                  absolute path to the slice cache file.
 * ready:                 1 = file exists and is complete (xrootd_cache_file_ready).
 */
typedef struct {
    off_t       file_start;
    off_t       file_end;
    off_t       req_start;
    off_t       req_end;
    ngx_uint_t  idx;
    char        path[PATH_MAX];
    int         ready;
} xrootd_slice_t;

/*
 * xrootd_slice_path — build the absolute path for one slice file.
 * out = "<cache_path>.__xrds_<slice_size/1024>k_<slice_idx>".
 * Returns NGX_OK or NGX_ERROR (path too long / bad args).
 */
ngx_int_t xrootd_slice_path(const char *cache_path, size_t slice_size,
    ngx_uint_t slice_idx, char *out, size_t outsz);

/*
 * xrootd_slice_enumerate — find all slices covering [req_start, req_end).
 *
 * On return out[0..*nout-1] are the covering slices in ascending order; each
 * has .ready set from xrootd_cache_file_ready().  req_end is clamped to
 * file_size when file_size > 0.
 *
 * Returns NGX_OK if at least one slice was found, NGX_DECLINED if the request
 * spans more than max_out slices (caller returns 416), or NGX_ERROR on bad args.
 */
ngx_int_t xrootd_slice_enumerate(const char *cache_path, off_t file_size,
    size_t slice_size, off_t req_start, off_t req_end,
    xrootd_slice_t *out, ngx_uint_t max_out, ngx_uint_t *nout);

/*
 * xrootd_slice_meta_base — build the base path the cache meta helpers append
 * ".meta" to, i.e. "<cache_path>.__xrds".  The resulting sidecar
 * "<cache_path>.__xrds.meta" never collides with a per-slice file.
 */
ngx_int_t xrootd_slice_meta_base(const char *cache_path,
    char *out, size_t outsz);

/*
 * xrootd_slice_meta_validate — check the file-level meta against the origin.
 *
 * Returns:
 *   NGX_OK       — meta matches, or no meta exists yet (caller treats as unknown)
 *   NGX_DECLINED — mismatch: file changed at origin; all slices are stale
 *   NGX_ERROR    — I/O error reading the meta file
 */
ngx_int_t xrootd_slice_meta_validate(const char *cache_path,
    off_t origin_size, const char *origin_etag, ngx_log_t *log);

/*
 * xrootd_slice_meta_write — persist file-level meta (origin size/etag/mtime).
 */
ngx_int_t xrootd_slice_meta_write(const char *cache_path,
    off_t origin_size, const char *origin_etag, uint64_t mtime,
    ngx_log_t *log);

/*
 * xrootd_slice_evict_all — remove every slice file and the meta sidecar for
 * one cached file via glob("<cache_path>.__xrds_*") + unlink, plus the meta.
 * Returns the number of files removed.
 */
ngx_uint_t xrootd_slice_evict_all(const char *cache_path, ngx_log_t *log);

#endif /* XROOTD_CACHE_SLICE_H */
