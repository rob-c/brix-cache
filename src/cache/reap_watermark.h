#ifndef XROOTD_CACHE_REAP_WATERMARK_H
#define XROOTD_CACHE_REAP_WATERMARK_H

/*
 * reap_watermark.h — proactive, watermark-driven LRU reaper for the read cache.
 *
 * WHAT: A background per-worker timer that purges the read cache oldest-first
 *       when filesystem occupancy crosses the HIGH watermark, down to the LOW
 *       watermark (hysteresis), independent of cache fills.
 *
 * WHY:  The on-fill safety net (xrootd_cache_evict_if_needed) only runs while
 *       the cache is being written. A cache that fills and then goes quiet would
 *       never shrink. The timer keeps occupancy bounded under any traffic shape,
 *       the way XCache's periodic purge does.
 *
 * HOW:  xrootd_cache_watermark_purge() samples occupancy (TTL-cached), and if it
 *       exceeds HIGH takes the cross-worker eviction lock and drives the shared
 *       engine xrootd_cache_purge_to_target() down to LOW. The timer handler
 *       re-arms itself at cache_reap_interval.
 */

#include "cache_internal.h"

/*
 * One proactive purge pass. When cache_root occupancy exceeds cache_high_watermark,
 * reap oldest-first down to cache_low_watermark; dirty write-back files are never
 * reaped (skipped by the candidate collector). Takes the cross-worker eviction
 * lock; a no-op when calm, when another worker holds the lock, or on a statvfs
 * error (logged, fail-safe). Returns the number of files evicted. No connection
 * context required.
 */
ngx_uint_t xrootd_cache_watermark_purge(ngx_stream_xrootd_srv_conf_t *conf,
    ngx_log_t *log);

/*
 * Per-worker background timer handler (ev->data = the srv conf). Calls
 * xrootd_cache_watermark_purge() and re-arms at conf->cache_reap_interval until
 * the worker is exiting.
 */
void xrootd_cache_watermark_timer_handler(ngx_event_t *ev);

#endif /* XROOTD_CACHE_REAP_WATERMARK_H */
