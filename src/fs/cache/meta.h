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

/*
 * §9 .cinfo upgrade: the record grows a versioned tail (access stats + origin
 * checksum) AFTER the legacy {mtime,size,etag_len,etag} base. Readers accept a
 * legacy-sized sidecar (the tail reads short and stays zeroed → version 0); a
 * grown record is detected by version >= 1. The base layout is unchanged so old
 * code paths and on-disk validity checks are byte-compatible.
 */
#define XROOTD_CACHE_META_VERSION 1

typedef struct {
    /* ---- legacy base (do not reorder/resize) ---- */
    uint64_t mtime;
    uint64_t size;
    uint8_t  etag_len;
    char     etag[XROOTD_CACHE_META_ETAG_MAX];
    /* ---- §9 versioned tail (zeroed when reading a legacy sidecar) ---- */
    uint8_t  version;           /* 0 = legacy (no tail), >=1 = cinfo */
    uint64_t access_count;      /* cache hits served */
    uint64_t last_access;       /* unix secs of the most recent hit */
    uint64_t bytes_served;      /* cumulative bytes served from cache */
    uint8_t  cks_alg_len;       /* origin checksum algo name length (0 = none) */
    char     cks_alg[16];       /* origin checksum algo name */
    uint8_t  cks_len;           /* origin checksum hex length (0 = none) */
    char     cks_hex[129];      /* origin checksum, lowercase hex, NUL-term */
} xrootd_cache_meta_t;

/* Size of the legacy on-disk base (everything before the versioned tail). */
#define XROOTD_CACHE_META_BASE_SIZE \
    (offsetof(xrootd_cache_meta_t, version))

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

/*
 * §9: record a cache hit — read the sidecar, bump access_count + bytes_served and
 * set last_access=now, upgrade it to a versioned (cinfo) record, and write it back.
 * Best-effort: a missing/unreadable sidecar is a no-op (NGX_DECLINED). nbytes is the
 * number of bytes served by this hit. Returns NGX_OK on a successful update.
 */
ngx_int_t xrootd_cache_meta_touch(ngx_log_t *log, const char *cache_path,
    uint64_t nbytes);

#endif /* XROOTD_CACHE_META_H */
