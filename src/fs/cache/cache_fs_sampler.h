#ifndef XROOTD_CACHE_FS_USAGE_H
#define XROOTD_CACHE_FS_USAGE_H

/*
 * fs_usage.h — the pure freshness predicate behind the TTL-cached statvfs
 * sampler (xrootd_cache_fs_usage_sampled, implemented in fs_usage.c).
 *
 * Kept header-only and nginx-free so the unit test links it without stubs, the
 * same split cache_key.c uses for its pure key derivation. The nginx-typed
 * sampler declaration lives in evict_internal.h.
 */

#include <stdint.h>

/*
 * xrootd_cache_sample_fresh — is a sample taken at last_ms still usable at
 * now_ms for the given ttl_ms?
 *
 *   last_ms == 0   → "never sampled" → always stale (re-sample).
 *   now_ms < last_ms → clock stepped backward → stale (self-heal, re-sample).
 *   else           → fresh iff age (now_ms - last_ms) is strictly < ttl_ms,
 *                    so ttl_ms == 0 forces a re-sample on every call.
 *
 * Pure; uses a monotonic millisecond clock (ngx_current_msec at the call site).
 */
static inline int
xrootd_cache_sample_fresh(uint64_t now_ms, uint64_t last_ms, uint64_t ttl_ms)
{
    if (last_ms == 0 || now_ms < last_ms) {
        return 0;
    }
    return (now_ms - last_ms) < ttl_ms;
}

#endif /* XROOTD_CACHE_FS_USAGE_H */
