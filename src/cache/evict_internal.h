/*
 * evict_internal.h — shared types, macro, and function declarations for the
 * cache eviction subsystem (evict_candidates.c and evict_policy.c).
 *
 * Include this header from both fragments; it brings in cache_internal.h
 * (which itself includes ngx_xrootd_module.h and wraps everything in
 * #if (NGX_THREADS)).
 */
#pragma once

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

ngx_int_t xrootd_cache_fs_usage(const char *root,
    xrootd_cache_fs_usage_t *usage);
ngx_int_t xrootd_cache_try_evict_lock(ngx_stream_xrootd_srv_conf_t *conf,
    char *lock_path, size_t lock_pathsz, ngx_log_t *log);
void xrootd_cache_evict_unlock(const char *lock_path);
ngx_int_t xrootd_cache_collect_dir(xrootd_cache_evict_list_t *list,
    const char *dir, ngx_log_t *log);
int  xrootd_cache_candidate_cmp(const void *a, const void *b);
void xrootd_cache_free_candidates(xrootd_cache_evict_list_t *list);

