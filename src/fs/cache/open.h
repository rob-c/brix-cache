#ifndef XROOTD_CACHE_OPEN_H
#define XROOTD_CACHE_OPEN_H

#include "fs/vfs/vfs.h"

/*
 * open.h — read-side cache-hit path: serve a file from the local cache tree.
 *
 * Public contract for the VFS cache-open hook plus its path-mapping and
 * LRU-touch helpers. Implementations live in src/cache/open.c.
 */

/*
 * VFS cache-open hook: serve a read from the cache when a complete, fresh copy
 * exists, otherwise tell the caller to fall back to the origin. ctx is borrowed
 * (not retained). Sets *fh_out to NULL up front, then on a validated hit opens
 * the cache file read-only and adopts the fd (xrootd_vfs_adopt_fd), returning
 * NGX_OK with *fh_out set. Returns NGX_DECLINED (do not serve from cache, no
 * error) when caching is disabled, XROOTD_VFS_O_NOCACHE is set, any
 * write/create/trunc/append flag is present, or on miss / not-ready / stale meta.
 * Returns NGX_ERROR on a hard I/O failure with errno set.
 */
ngx_int_t xrootd_cache_open(xrootd_vfs_ctx_t *ctx, ngx_uint_t flags,
    xrootd_vfs_file_t **fh_out);

/*
 * Refresh cache_path's access time (atime only) so the eviction pass treats it
 * as recently used. The bytes argument is currently ignored. Returns NGX_OK on
 * success or where UTIME_OMIT is unavailable (no-op), NGX_ERROR on NULL/empty
 * path or a failed utimensat (errno set; failure also logged at DEBUG if log).
 */
ngx_int_t xrootd_cache_record_access(const char *cache_path, size_t bytes,
    ngx_log_t *log);

/*
 * Map a resolved export path to its cache-tree path: strip root_canon and
 * re-root the suffix under cache_root_canon, writing a NUL-terminated result to
 * out (capacity outsz). This is a pure lexical remap, NOT a confinement check.
 * Returns NGX_OK, or NGX_ERROR (errno set) on NULL/empty args or a resolved
 * path not under root_canon (EINVAL), or a result that would overflow out
 * (ENAMETOOLONG).
 */
ngx_int_t xrootd_cache_path_for_resolved(const char *cache_root_canon,
    const char *root_canon, const char *resolved, char *out, size_t outsz);

#endif /* XROOTD_CACHE_OPEN_H */
