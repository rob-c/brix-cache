#ifndef XROOTD_CACHE_META_H
#define XROOTD_CACHE_META_H

/*
 * meta.h — on-disk cache-validity metadata sidecar interface.
 *
 * WHAT: Defines xrootd_cache_meta_t (origin mtime, size, and a bounded etag)
 *       and the read/write/derive API implemented in meta.c, plus the
 *       XROOTD_CACHE_META_ETAG_MAX bound on the inline etag field.
 *
 * WHY:  Each cached file gets a companion sidecar so the cache can prove a
 *       local copy still matches the origin before serving it. Centralising the
 *       record layout here keeps the writer (meta.c), the validator (open.c),
 *       eviction (evict_policy.c), and the slice cache (slice.h) byte-compatible.
 *
 * HOW:  The record is a fixed-size POD struct read/written verbatim, so its
 *       layout is the on-disk format — fields must not be reordered or resized
 *       without invalidating existing sidecars. xrootd_cache_meta_path() (in
 *       paths.c) maps a cache file path to its sidecar path; the remaining
 *       helpers operate on that path.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>
#include <sys/stat.h>

#define XROOTD_CACHE_META_ETAG_MAX 55

typedef struct {
    uint64_t mtime;
    uint64_t size;
    uint8_t  etag_len;
    char     etag[XROOTD_CACHE_META_ETAG_MAX];
} xrootd_cache_meta_t;

/*
 * Map a cache file path to its sidecar path by appending the ".meta" suffix.
 * Writes the result into the caller-owned dst[dstsz]; returns 0 on success,
 * -1 if the result (with suffix and NUL) would not fit in dstsz.
 */
int xrootd_cache_meta_path(char *dst, size_t dstsz, const char *cache_path);

/*
 * Build an in-memory meta record from a stat plus an optional etag (NULL/empty
 * for none). Borrows both inputs (copies st->st_mtime/st_size and up to
 * XROOTD_CACHE_META_ETAG_MAX etag bytes, silently truncating longer etags) into
 * the caller-owned *meta, which it first zeroes. Returns NGX_OK; NGX_ERROR (sets
 * errno EINVAL) only if st or meta is NULL.
 */
ngx_int_t xrootd_cache_meta_from_stat(const struct stat *st, const char *etag,
    xrootd_cache_meta_t *meta);

/*
 * Load the sidecar record for cache_path into the caller-owned *meta. log is
 * unused. Returns NGX_OK on a full valid read; NGX_DECLINED (treat as cache
 * miss) when the sidecar is absent (ENOENT), truncated, or has an out-of-range
 * etag_len; NGX_ERROR (errno set) on any other I/O failure or NULL argument.
 */
ngx_int_t xrootd_cache_meta_read(ngx_log_t *log, const char *cache_path,
    xrootd_cache_meta_t *meta);

/*
 * Persist *meta to the sidecar for cache_path (O_CREAT|O_TRUNC, mode 0644),
 * zero-padding the unused etag tail for a stable on-disk image; *meta is
 * borrowed, not modified. log is unused. Returns NGX_OK on a full write;
 * NGX_ERROR (errno set) on NULL/out-of-range etag_len arguments or any I/O
 * failure, including a failed close after an otherwise successful write.
 */
ngx_int_t xrootd_cache_meta_write(ngx_log_t *log, const char *cache_path,
    const xrootd_cache_meta_t *meta);

#endif /* XROOTD_CACHE_META_H */
