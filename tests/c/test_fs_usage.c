/*
 * test_fs_usage.c — the pure freshness predicate behind the TTL-cached statvfs
 * sampler (xrootd_cache_fs_usage_sampled). The nginx-coupled glue (slot table,
 * statvfs) is covered by the e2e; this isolates the cache-validity decision.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/fs/cache/cache_fs_sampler.h"   /* xrootd_cache_sample_fresh (pure inline) */

int main(void) {
    /* never sampled (last_ms == 0) → always stale, regardless of ttl */
    assert(xrootd_cache_sample_fresh(1000, 0, 5000) == 0);
    assert(xrootd_cache_sample_fresh(0,    0, 5000) == 0);

    /* within ttl → fresh */
    assert(xrootd_cache_sample_fresh(1500, 1000, 1000) == 1);   /* age 500 < 1000 */
    assert(xrootd_cache_sample_fresh(1999, 1000, 1000) == 1);   /* age 999 < 1000 */

    /* exactly ttl or older → stale (strict <) */
    assert(xrootd_cache_sample_fresh(2000, 1000, 1000) == 0);   /* age 1000 */
    assert(xrootd_cache_sample_fresh(9000, 1000, 1000) == 0);

    /* ttl == 0 → always stale (force re-sample every call) */
    assert(xrootd_cache_sample_fresh(1001, 1000, 0) == 0);

    /* clock stepped backward (now < last) → stale, self-healing */
    assert(xrootd_cache_sample_fresh(900, 1000, 5000) == 0);

    printf("test_fs_usage: ALL PASS\n");
    return 0;
}
