/*
 * reap_watermark.c — proactive watermark-driven LRU reaper. See the header.
 */

#include "reap_watermark.h"
#include "evict_internal.h"   /* fs_usage sampler + purge_to_target + the lock */
#include "observability/metrics/unified.h"   /* dedicated watermark-reaper telemetry */

#include <limits.h>

/*
 * brix_cache_purge_to_max_bytes — evict oldest-first until the cache's OWN bytes
 * fall to `max_bytes` (audit §4.7, upstream `pfc.diskusage files`).
 *
 * WHAT: Sums the size of every cached object this node holds and, if that exceeds
 *       max_bytes, evicts oldest-first until it is back within the cap. Unlike the
 *       ppm engine this targets cache-OWNED bytes, not filesystem occupancy — so a
 *       cache that SHARES a filesystem with other data is bounded by what IT holds
 *       rather than by the whole mount's fullness. `max_bytes == 0` = off.
 * WHY:  On a shared filesystem statvfs reflects everyone's data: the FS watermark
 *       either never fires (huge mount) or thrashes (a noisy neighbour), so a cache
 *       needs a cap on its own footprint too. Same candidate set + same
 *       brix_cache_evict_one primitive as the ppm engine (shared via
 *       evict_internal.h), so a victim is demoted / unregistered / sidecar-cleaned
 *       identically.
 * HOW:  Collect + sort oldest-first (shared collector), sum owned bytes, and if
 *       over the cap evict oldest-first tracking the remaining owned bytes as
 *       initial_owned - evicted_bytes (no per-unlink statvfs: skip_usage_remeasure
 *       is set). The CALLER owns the cross-worker eviction lock. Writes the evicted
 *       counts (out-pointers may be NULL); NGX_OK, or NGX_ERROR if the candidate
 *       collection could not start (e.g. the cache root vanished).
 */
ngx_int_t
brix_cache_purge_to_max_bytes(ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log,
    uint64_t max_bytes, ngx_uint_t *evicted_files_out,
    uint64_t *evicted_bytes_out)
{
    brix_cache_evict_list_t list;
    brix_cache_fs_usage_t   usage;       /* unused target — evict_one skips it */
    brix_cache_evict_ctx_t  ec;
    const char             *phys_root;
    uint64_t                owned = 0;
    size_t                  i;

    if (evicted_files_out != NULL) { *evicted_files_out = 0; }
    if (evicted_bytes_out != NULL) { *evicted_bytes_out = 0; }

    if (conf == NULL || max_bytes == 0) {
        return NGX_OK;
    }
    phys_root = brix_cache_state_root(conf);
    if (phys_root == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&ec, sizeof(ec));
    ec.conf  = conf;
    ec.log   = log;
    ec.list  = &list;
    ec.usage = &usage;
    ec.skip_usage_remeasure = 1;         /* bytes target, not FS occupancy */

    if (brix_cache_collect_and_sort(&ec, phys_root, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < list.nelts; i++) {
        if (list.elts[i].size > 0) {
            owned += (uint64_t) list.elts[i].size;
        }
    }

    /* Evict oldest-first while the still-owned bytes (initial minus what we have
     * already reclaimed) exceed the cap. evict_one accumulates ec.evicted_bytes. */
    if (owned > max_bytes) {
        for (i = 0; i < list.nelts
             && (owned - ec.evicted_bytes) > max_bytes; i++)
        {
            if (list.evicted[i]) {
                continue;
            }
            (void) brix_cache_evict_one(&ec, i);   /* skip_usage → always NGX_OK */
        }
    }

    brix_cache_free_candidates(&list);

    if (evicted_files_out != NULL) { *evicted_files_out = ec.evicted_files; }
    if (evicted_bytes_out != NULL) { *evicted_bytes_out = ec.evicted_bytes; }
    return NGX_OK;
}

ngx_uint_t
brix_cache_watermark_purge(ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log)
{
    brix_cache_fs_usage_t usage;
    char                    lock_path[PATH_MAX];
    ngx_uint_t              evicted_files = 0;
    uint64_t                evicted_bytes = 0;
    int                     cache_active;
    const char             *phys_root;
    int                     fs_wm_on;     /* the ppm FS-occupancy watermark armed */
    int                     files_wm_on;  /* the owned-bytes (max_bytes) cap armed */
    int                     fs_over = 0;

    if (conf == NULL) {
        return 0;
    }
    /* §14a unification: a cache is active under EITHER the legacy activation
     * (conf->cache, set by brix_cache on) OR the composable tier grammar (a
     * cache_store, conf->cache==0). The physical dir the reaper walks comes from
     * brix_cache_state_root, now tier-aware (returns the posix cache_store dir). */
    cache_active = (conf->cache != 0) || (conf->common.cache_store.len > 0);
    phys_root    = brix_cache_state_root(conf);
    if (!cache_active || phys_root == NULL) {
        return 0;
    }

    fs_wm_on = (conf->reaper.high_watermark != 0
                && conf->reaper.high_watermark < BRIX_CACHE_PPM_FULL_SCALE);
    files_wm_on = (conf->reaper.max_bytes > 0);
    if (!fs_wm_on && !files_wm_on) {
        return 0;                            /* neither watermark armed */
    }

    /*
     * FS-occupancy arm: cheap pre-check off the TTL-cached sampler (1s) — avoid
     * taking the cross-worker lock while the cache is calm. A statvfs failure is a
     * monitoring fault, not a cache fault: log-and-skip the FS arm, but still run
     * the owned-bytes arm below (which needs no statvfs).
     */
    if (fs_wm_on) {
        if (brix_cache_fs_usage_sampled((char *) phys_root, 1000, &usage)
            == NGX_OK)
        {
            brix_metric_cache_usage_ratio(usage.occupancy_ppm);
            fs_over = (usage.occupancy_ppm > conf->reaper.high_watermark);
        } else {
            ngx_log_error(NGX_LOG_WARN, log, errno,
                "brix: watermark reaper could not stat cache root \"%s\"",
                phys_root);
        }
    }

    /* Nothing to do: FS below its mark (or unarmed) and no owned-bytes cap. The
     * owned-bytes arm has no cheap statvfs proxy, so when it is armed we always
     * proceed to take the lock and let the purge measure + decide. */
    if (!fs_over && !files_wm_on) {
        return 0;
    }

    ngx_memzero(lock_path, sizeof(lock_path));
    if (brix_cache_try_evict_lock(conf, lock_path, sizeof(lock_path), log)
        != NGX_OK)
    {
        return 0;                            /* another worker is purging */
    }

    /* FS arm: reap down to the LOW watermark (hysteresis), oldest-first. */
    if (fs_over) {
        ngx_uint_t ef = 0;
        uint64_t   eb = 0;
        (void) brix_cache_purge_to_target(conf, NULL, NULL, NULL,
                  conf->reaper.low_watermark, log, &ef, &eb);
        evicted_files += ef;
        evicted_bytes += eb;
    }
    /* Owned-bytes arm: reap down to the byte cap, oldest-first (§4.7). Reuses the
     * same candidate set + evict primitive; measures the cache's own footprint. */
    if (files_wm_on) {
        ngx_uint_t ef = 0;
        uint64_t   eb = 0;
        (void) brix_cache_purge_to_max_bytes(conf, log,
                  (uint64_t) conf->reaper.max_bytes, &ef, &eb);
        evicted_files += ef;
        evicted_bytes += eb;
    }

    brix_cache_evict_unlock(lock_path);

    if (evicted_files > 0) {
        brix_metric_cache_watermark_purge(evicted_files, evicted_bytes);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "brix: watermark reaper purged %ui file(s), %uL bytes "
                      "from \"%s\"",
                      evicted_files, (uint64_t) evicted_bytes, phys_root);
    }
    return evicted_files;
}

void
brix_cache_watermark_timer_handler(ngx_event_t *ev)
{
    ngx_stream_brix_srv_conf_t *conf = ev->data;

    (void) brix_cache_watermark_purge(conf, ev->log);

    if (!ngx_exiting) {
        time_t interval = (conf->reaper.reap_interval > 0)
                          ? conf->reaper.reap_interval : 60;
        ngx_add_timer(ev, (ngx_msec_t) interval * 1000);
    }
}
