/*
 * list_cache.h — per-worker LRU cache of sorted ListObjects results (W6c).
 *
 * WHAT: caches the *sorted* (key + is_prefix) list produced by a full bucket
 *   walk, keyed by (root, prefix, delimiter), so paginating a large bucket page
 *   by page does not re-walk + re-sort the whole subtree on every request
 *   (turning the per-bucket listing cost from O(n^2) back into O(n) amortised).
 *
 * WHY (design): the cache is process-local (per nginx worker) rather than SHM.
 *   The shared KV store reserves a fixed key_max+val_max stride per slot, so a
 *   value large enough to hold a big sorted listing would waste that much memory
 *   on every slot and still cap the listing size — i.e. it cannot cache exactly
 *   the large buckets that benefit most.  A heap LRU sizes each entry to its
 *   actual content and is not shared across workers (each warms its own; the
 *   listing is still O(n) amortised per worker).
 *
 * CONSISTENCY: a cached listing is reused only while the bucket-root directory
 *   mtime is unchanged AND within the configured TTL.  Root mtime catches
 *   top-level mutations; the TTL bounds staleness from deeper-subtree changes.
 *   This is bounded eventual consistency (S3 ListObjects is historically
 *   eventually-consistent), and the feature is opt-in (default off) so
 *   strongly-consistent deployments leave it disabled.
 */

#ifndef NGX_HTTP_S3_LIST_CACHE_H
#define NGX_HTTP_S3_LIST_CACHE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "s3.h"

/* Listings larger than this are not cached (bounds per-slot heap use); the walk
 * runs every time for such buckets — logged once so the cap is never silent. */
#define S3_LIST_CACHE_MAX_ENTRIES  20000

/*
 * s3_list_cache_get — on a fresh hit, allocate an s3_entry_t array in r->pool
 * (keys duplicated into the pool, stat fields zeroed for lazy fill) and return 1
 * with *out_items / *out_n set; otherwise return 0.  A stale entry (mtime
 * changed or TTL expired) is evicted and reported as a miss.
 */
int s3_list_cache_get(ngx_http_request_t *r, const char *root,
    const char *prefix, const char *delimiter, time_t dir_mtime,
    ngx_msec_t ttl_ms, s3_entry_t **out_items, int *out_n);

/*
 * s3_list_cache_put — store a copy of the sorted [items, n) list under
 * (root, prefix, delimiter, dir_mtime), evicting the LRU slot if full.  No-op
 * (logged once) when n exceeds S3_LIST_CACHE_MAX_ENTRIES.
 */
void s3_list_cache_put(ngx_log_t *log, const char *root, const char *prefix,
    const char *delimiter, time_t dir_mtime, const s3_entry_t *items, int n);

#endif /* NGX_HTTP_S3_LIST_CACHE_H */
