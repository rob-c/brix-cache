/*
 * reap_watermark.c — proactive watermark-driven LRU reaper. See the header.
 */

#include "reap_watermark.h"
#include "evict_internal.h"   /* fs_usage sampler + purge_to_target + the lock */
#include "../metrics/unified.h"   /* dedicated watermark-reaper telemetry */

#include <limits.h>

ngx_uint_t
xrootd_cache_watermark_purge(ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log)
{
    xrootd_cache_fs_usage_t usage;
    char                    lock_path[PATH_MAX];
    ngx_uint_t              evicted_files = 0;
    uint64_t                evicted_bytes = 0;

    if (conf == NULL || !conf->cache || conf->cache_root.len == 0
        || conf->cache_high_watermark == 0
        || conf->cache_high_watermark >= 1000000)
    {
        return 0;
    }

    /*
     * Cheap pre-check off the TTL-cached sampler (1s) — avoid taking the
     * cross-worker lock while the cache is calm. A statvfs failure here is a
     * monitoring fault, not a cache fault: log-and-skip rather than wedge.
     */
    if (xrootd_cache_fs_usage_sampled((char *) conf->cache_root.data, 1000,
                                      &usage) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd: watermark reaper could not stat cache_root \"%V\"",
                      &conf->cache_root);
        return 0;
    }

    /* Publish occupancy as a gauge every tick, whether or not we purge. */
    xrootd_metric_cache_usage_ratio(usage.occupancy_ppm);

    if (usage.occupancy_ppm <= conf->cache_high_watermark) {
        return 0;                            /* below the high mark — nothing to do */
    }

    ngx_memzero(lock_path, sizeof(lock_path));
    if (xrootd_cache_try_evict_lock(conf, lock_path, sizeof(lock_path), log)
        != NGX_OK)
    {
        return 0;                            /* another worker is purging */
    }

    /* Reap down to the LOW watermark (hysteresis), oldest-first. No connection
     * context (NULL ctx/c): the dedicated SHM metrics are emitted below. */
    (void) xrootd_cache_purge_to_target(conf, NULL, NULL, NULL,
              conf->cache_low_watermark, log, &evicted_files, &evicted_bytes);

    xrootd_cache_evict_unlock(lock_path);

    if (evicted_files > 0) {
        xrootd_metric_cache_watermark_purge(evicted_files, evicted_bytes);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "xrootd: watermark reaper purged %ui file(s), %uL bytes "
                      "from \"%V\" (low=0.%06ui)",
                      evicted_files, (uint64_t) evicted_bytes,
                      &conf->cache_root, conf->cache_low_watermark);
    }
    return evicted_files;
}

void
xrootd_cache_watermark_timer_handler(ngx_event_t *ev)
{
    ngx_stream_xrootd_srv_conf_t *conf = ev->data;

    (void) xrootd_cache_watermark_purge(conf, ev->log);

    if (!ngx_exiting) {
        time_t interval = (conf->cache_reap_interval > 0)
                          ? conf->cache_reap_interval : 60;
        ngx_add_timer(ev, (ngx_msec_t) interval * 1000);
    }
}
