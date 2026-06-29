/*
* cache_fs_sampler.c — TTL-cached statvfs sampler for the cache fullness signals.
 *
 * WHAT: xrootd_cache_fs_usage_sampled() wraps xrootd_cache_fs_usage() (a raw
 *       statvfs) with a tiny per-worker, per-root cache so hot callers do not
 *       statvfs on every request.
 *
 * WHY:  Two consumers need filesystem occupancy: the watermark reaper timer
 *       (cache_root, once per tick — cheap either way) and the write-back
 *       staging admission gate (stage_root, once per write-open — hot). A short
 *       TTL keeps the staging gate's per-open cost near zero while staying fresh
 *       enough to track fill/drain within a tick.
 *
 * HOW:  A fixed slot table keyed by the root string. On a hit younger than ttl
 *       (xrootd_cache_sample_fresh) the cached snapshot is returned; otherwise a
 *       fresh statvfs refreshes the slot. Per-worker (event loop + the fill
 *       worker that calls eviction are serialized w.r.t. their own roots in
 *       practice); the table is advisory, so a benign race only costs an extra
 *       statvfs. No allocation.
 */

#include "evict_internal.h"   /* xrootd_cache_fs_usage + the _sampled declaration */
#include "cache_fs_sampler.h"         /* xrootd_cache_sample_fresh (pure) */

#include <limits.h>
#include <string.h>

#define XROOTD_FS_USAGE_SLOTS 8

typedef struct {
    char                    root[PATH_MAX];
    uint64_t                last_ms;          /* 0 == empty/never sampled */
    xrootd_cache_fs_usage_t usage;
} fs_usage_slot_t;

static fs_usage_slot_t fs_usage_cache[XROOTD_FS_USAGE_SLOTS];

/* Find the slot for `root`, or the first empty slot to claim, or NULL when the
 * table is full and `root` is absent (caller reuses slot 0 as an LRU-ish victim). */
static fs_usage_slot_t *
fs_usage_lookup(const char *root, fs_usage_slot_t **free_out)
{
    fs_usage_slot_t *empty = NULL;
    ngx_uint_t       i;

    for (i = 0; i < XROOTD_FS_USAGE_SLOTS; i++) {
        if (fs_usage_cache[i].last_ms != 0
            && strcmp(fs_usage_cache[i].root, root) == 0)
        {
            return &fs_usage_cache[i];
        }
        if (fs_usage_cache[i].last_ms == 0 && empty == NULL) {
            empty = &fs_usage_cache[i];
        }
    }
    *free_out = empty;
    return NULL;
}

ngx_int_t
xrootd_cache_fs_usage_sampled(const char *root, ngx_msec_t ttl_ms,
    xrootd_cache_fs_usage_t *out)
{
    uint64_t                 now = (uint64_t) ngx_current_msec;
    fs_usage_slot_t         *slot;
    fs_usage_slot_t         *empty = NULL;
    xrootd_cache_fs_usage_t  fresh;

    if (root == NULL || out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    slot = fs_usage_lookup(root, &empty);
    if (slot != NULL
        && xrootd_cache_sample_fresh(now, slot->last_ms, (uint64_t) ttl_ms))
    {
        *out = slot->usage;
        return NGX_OK;
    }

    if (xrootd_cache_fs_usage(root, &fresh) != NGX_OK) {
        return NGX_ERROR;          /* leave any stale slot in place; caller decides */
    }

    if (slot == NULL) {
        slot = (empty != NULL) ? empty : &fs_usage_cache[0];   /* victim when full */
        ngx_snprintf((u_char *) slot->root, sizeof(slot->root) - 1, "%s%Z", root);
    }
    slot->usage   = fresh;
    slot->last_ms = (now == 0) ? 1 : now;   /* never store 0 — that means "empty" */

    *out = fresh;
    return NGX_OK;
}
