/*
 * evict_internal.h — shared types, macro, and function declarations for the
 * cache eviction subsystem (evict_candidates.c and evict_policy.c).
 *
 * Include this header from both fragments; it brings in cache_internal.h
 * (which itself includes ngx_xrootd_module.h and wraps everything in
 * #if (NGX_THREADS)).
 */
#ifndef XROOTD_CACHE_EVICT_INTERNAL_H
#define XROOTD_CACHE_EVICT_INTERNAL_H

#include "cache_internal.h"
#include "../manager/registry.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>


/*
 * Increment a cache metrics counter.  Safe to call with a NULL ctx.
 */
#define xrootd_cache_metric_add(ctx, member, value)                      \
    do {                                                                 \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                    \
            ngx_atomic_fetch_add(&(ctx)->metrics->member,                 \
                                 (ngx_atomic_int_t) (value));             \
        }                                                                \
    } while (0)

/*
 * xrootd_cache_evict_candidate_t — a single candidate file for eviction.
 */
typedef struct {
    char   *path;    /* heap-allocated absolute path; freed by
                      * xrootd_cache_free_candidates() */
    off_t   size;    /* file size in bytes (from lstat) */
    time_t  atime;   /* last access time — primary LRU sort key */
    time_t  mtime;   /* last modification time — secondary sort key */
} xrootd_cache_evict_candidate_t;

/*
 * xrootd_cache_evict_list_t — growable array of eviction candidates.
 */
typedef struct {
    xrootd_cache_evict_candidate_t *elts;  /* dynamically grown array */
    size_t                          nelts; /* number of valid entries */
    size_t                          cap;   /* allocated capacity */
    dev_t                           root_dev;      /* only evict files on
                                                    * this device */
    const char                     *protect_path;  /* skip this path even
                                                    * if oldest (in-flight) */
    char                           *evicted;       /* parallel bool array:
                                                    * 1 if already unlinked */
} xrootd_cache_evict_list_t;

/*
 * xrootd_cache_fs_usage_t — filesystem space statistics.
 */
typedef struct {
    uint64_t    total;           /* filesystem total bytes */
    uint64_t    used;            /* bytes in use (blocks - bavail) */
    uint64_t    available;       /* bytes available to unprivileged user */
    ngx_uint_t  occupancy_ppm;   /* used/total in parts-per-million (0-1000000) */
} xrootd_cache_fs_usage_t;

/* ---- evict_candidates.c helpers called from evict_policy.c -------------- */

/*
 * Fill *usage with the filesystem space stats for the mount containing `root`
 * (via statvfs). occupancy_ppm is used/total in parts-per-million.
 * Returns NGX_OK, or NGX_ERROR if statvfs fails or the filesystem is empty
 * (f_blocks == 0). *usage is left untouched on NGX_ERROR.
 */
ngx_int_t xrootd_cache_fs_usage(const char *root,
    xrootd_cache_fs_usage_t *usage);

/*
 * Try to acquire the cross-worker eviction lock (an O_CREAT|O_EXCL sentinel
 * file under conf->cache_root). On success writes the sentinel path into
 * lock_path (caller-owned buffer of lock_pathsz bytes); the caller must later
 * release it with xrootd_cache_evict_unlock(). A sentinel older than
 * conf->cache_lock_timeout seconds is treated as stale and reclaimed.
 * Returns NGX_OK (lock held), NGX_DECLINED (another worker holds a fresh lock
 * or a race lost the reclaim — skip eviction), or NGX_ERROR (path too long /
 * unexpected OS error; errno set).
 */
ngx_int_t xrootd_cache_try_evict_lock(ngx_stream_xrootd_srv_conf_t *conf,
    char *lock_path, size_t lock_pathsz, ngx_log_t *log);

/*
 * Release the eviction sentinel lock by unlinking lock_path; no-op if
 * lock_path is the empty string. Call exactly once per NGX_OK from
 * xrootd_cache_try_evict_lock(); errors from unlink() are ignored.
 */
void xrootd_cache_evict_unlock(const char *lock_path);

/*
 * Recursively scan directory `dir`, appending every regular file as an
 * eviction candidate to *list (allocating list->elts via malloc/realloc;
 * each candidate->path is a freshly malloc'd copy owned by the list).
 * Skips special names (. / .. / lock sentinel / *.part / *.lock) and entries
 * whose st_dev differs from list->root_dev (other mounts).
 * Returns NGX_OK, or NGX_ERROR if any entry failed (opendir/lstat/path-overflow
 * or candidate allocation); partial results are still left in *list.
 */
ngx_int_t xrootd_cache_collect_dir(xrootd_cache_evict_list_t *list,
    const char *dir, ngx_log_t *log);

/*
 * qsort(3) comparator over xrootd_cache_evict_candidate_t for oldest-first
 * (LRU) ordering: ascending atime, then ascending mtime, then strcmp(path)
 * for a deterministic total order. Returns -1 / 0 / +1.
 */
int  xrootd_cache_candidate_cmp(const void *a, const void *b);

/*
 * Free every heap allocation owned by *list (each candidate->path, the elts
 * array, and the parallel evicted[] array) and reset its fields to empty.
 * The list struct itself is not freed (caller owns it). Safe to leave the
 * struct reusable afterward.
 */
void xrootd_cache_free_candidates(xrootd_cache_evict_list_t *list);

#endif /* XROOTD_CACHE_EVICT_INTERNAL_H */
