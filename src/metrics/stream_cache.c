#include "metrics_internal.h"
#include "core/compat/fs_usage.h"

/*
 * WHAT: Prometheus HTTP exporter for read-through cache metrics — filesystem occupancy, eviction counters,
 *      and configured thresholds per server listener.
 * WHY: The xrootd_cache_root provides XCache-style direct-mode fills from anonymous root:// origins. Cache
 *      behavior (eviction on high occupancy, bytes reclaimed, eviction errors) needs observable Prometheus
 *      gauges and counters so operators can tune cache_eviction_threshold_ratio and monitor fill efficiency.
 * HOW: xrootd_cache_statvfs() calls statvfs(2) on the configured root directory to compute total/used/available
 *      bytes and occupancy_ppm (parts per million). xrootd_export_stream_cache_metrics() iterates server slots,
 *      skips inactive/cache-disabled entries, emits occupancy_ratio gauge, eviction_threshold gauge, cache_bytes
 *      gauge with state labels (total/used/available), evictions_total counter, evicted_bytes_total counter,
 *      and eviction_errors_total counter — all with port/auth label pairs.
 */

/*
 * WHAT: Snapshot the filesystem occupancy of one cache root directory.
 * WHY:  Cache gauges (occupancy ratio, bytes by state) must reflect live disk
 *       usage at scrape time, so we re-stat per scrape rather than caching.
 * HOW:  Delegates to the shared xrootd_fs_usage_stat() (statvfs(2) wrapper) and
 *       unpacks its struct into the caller's out-params. occupancy_ppm is
 *       parts-per-million (used/total * 1e6) computed once by the helper so the
 *       caller need not redo the division. Returns NGX_ERROR if the root cannot
 *       be statted (e.g. unmounted/missing) — callers skip that server's row.
 */
static ngx_int_t
xrootd_cache_statvfs(const char *root, uint64_t *total, uint64_t *used,
    uint64_t *available, ngx_uint_t *occupancy_ppm)
{
    xrootd_fs_usage_t fsu;

    if (xrootd_fs_usage_stat(root, &fsu) != NGX_OK) {
        return NGX_ERROR;
    }

    *total = fsu.total_bytes;
    *available = fsu.available_bytes;
    *used = fsu.occupancy_bytes;
    *occupancy_ppm = fsu.occupancy_ppm;

    return NGX_OK;
}

/*
 * WHAT: Emit the full read-through-cache + write-through metric families to the
 *       Prometheus writer, one labelled row per active server listener.
 * WHY:  Each server block can have its own cache root, threshold, and counters,
 *       so every gauge/counter is fanned out across the SHM server slots and
 *       labelled by {port,auth} to stay low-cardinality (no paths as labels).
 * HOW:  Prometheus format requires all rows of a family to be grouped under a
 *       single HELP/TYPE block, hence the deliberate "one loop per family"
 *       shape rather than one loop emitting all metrics per server. Within each
 *       loop:
 *         - skip slots that are not in_use (free) and, for cache families, not
 *           cache_enabled — write-through families gate on in_use only;
 *         - render the numeric port into a NUL-terminated C string (see the
 *           %Z note below) for use with the "%s" label format;
 *         - counters are read with ngx_atomic_fetch_add(&x, 0): adding zero is
 *           the lock-free read idiom — it is NOT a mutation, just an atomic load.
 *       The two statvfs-backed families re-stat per server each time (cheap,
 *       and keeps the gauge fresh); intervening families need no syscall.
 */
void
xrootd_export_stream_cache_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm)
{
    ngx_xrootd_srv_metrics_t *srv;
    ngx_uint_t                i;
    char                      port_str[16];

    /* OCCUPANCY RATIO gauge: live used/total, scaled from ppm to a 0..1 ratio. */
    mw_printf(mw,
        "# HELP xrootd_cache_occupancy_ratio "
            "Filesystem occupancy ratio for xrootd_cache_root.\n"
        "# TYPE xrootd_cache_occupancy_ratio gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        uint64_t   total, used, available;
        ngx_uint_t occupancy_ppm;

        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        if (xrootd_cache_statvfs(srv->cache_root, &total, &used,
                                 &available, &occupancy_ppm) != NGX_OK)
        {
            continue;
        }
        /* "%Z" appends a trailing '\0' so port_str is a valid C string for the
         * "%s" label below; ngx_snprintf does not NUL-terminate on its own. */
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        /* ppm (parts-per-million) -> ratio for Prometheus's 0..1 gauge convention. */
        mw_printf(mw,
            "xrootd_cache_occupancy_ratio{port=\"%s\",auth=\"%s\"} %0.6f\n",
            port_str, srv->auth, (double) occupancy_ppm / 1000000.0);
    }

    /* EVICTION THRESHOLD gauge: the configured high-water mark, also stored
     * as ppm in the SHM srv struct, rendered as a ratio for comparison against
     * the occupancy_ratio gauge above. No statvfs needed (config value only). */
    mw_printf(mw,
        "# HELP xrootd_cache_eviction_threshold_ratio "
            "Configured cache eviction high-water occupancy ratio.\n"
        "# TYPE xrootd_cache_eviction_threshold_ratio gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_eviction_threshold_ratio"
                "{port=\"%s\",auth=\"%s\"} %0.6f\n",
            port_str, srv->auth,
            (double) srv->cache_eviction_threshold / 1000000.0);
    }

    /* CACHE BYTES gauge: one family, three rows per server distinguished by the
     * state="total|used|available" label (the standard filesystem triple). */
    mw_printf(mw,
        "# HELP xrootd_cache_bytes "
            "Cache filesystem bytes by state.\n"
        "# TYPE xrootd_cache_bytes gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        uint64_t   total, used, available;
        ngx_uint_t occupancy_ppm;

        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        if (xrootd_cache_statvfs(srv->cache_root, &total, &used,
                                 &available, &occupancy_ppm) != NGX_OK)
        {
            continue;
        }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_bytes{port=\"%s\",auth=\"%s\",state=\"total\"} %llu\n",
            port_str, srv->auth, (unsigned long long) total);
        mw_printf(mw,
            "xrootd_cache_bytes{port=\"%s\",auth=\"%s\",state=\"used\"} %llu\n",
            port_str, srv->auth, (unsigned long long) used);
        mw_printf(mw,
            "xrootd_cache_bytes{port=\"%s\",auth=\"%s\",state=\"available\"} %llu\n",
            port_str, srv->auth, (unsigned long long) available);
    }

    /* EVICTION COUNTERS: files evicted / bytes reclaimed / maintenance errors.
     * Each is a monotonic SHM counter read atomically (fetch_add 0 == load). */
    mw_printf(mw,
        "# HELP xrootd_cache_evictions_total "
            "Files evicted from xrootd_cache_root.\n"
        "# TYPE xrootd_cache_evictions_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_evictions_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->cache_evictions_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_cache_evicted_bytes_total "
            "Bytes reclaimed by cache eviction.\n"
        "# TYPE xrootd_cache_evicted_bytes_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_evicted_bytes_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->cache_evicted_bytes_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_cache_eviction_errors_total "
            "Cache eviction maintenance errors.\n"
        "# TYPE xrootd_cache_eviction_errors_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_eviction_errors_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->cache_eviction_errors_total, 0));
    }

    /* DIRTY-REAP COUNTER: files removed by the stale-dirty reaper
     * (xrootd_cache_reap_dirty), split by the `reason` label (see
     * xrootd_cache_reap_reason_t): "abandoned" (un-flushed dirty discarded — data
     * loss), "incomplete" (re-dirtied after a prior flush — partial loss), and
     * "completed" (a finished write-back staging copy reclaimed — no loss). The
     * reaper scans the unified cache state root shared by the read-through and
     * write-through caches, so this is gated on in_use ONLY (like the write-through
     * families below) and reported for any active server with a cache-state root. */
    {
        static const char *const reap_reason[XROOTD_CACHE_REAP_REASON_COUNT] = {
            [XROOTD_CACHE_REAP_ABANDONED]  = "abandoned",
            [XROOTD_CACHE_REAP_INCOMPLETE] = "incomplete",
            [XROOTD_CACHE_REAP_COMPLETED]  = "completed",
        };
        ngx_uint_t r;

        mw_printf(mw,
            "# HELP xrootd_cache_dirty_reaped_total "
                "Cache files reaped by the stale-dirty reaper, by reason "
                "(abandoned/incomplete = write-back discarded; "
                "completed = finished staging reclaimed).\n"
            "# TYPE xrootd_cache_dirty_reaped_total counter\n");
        for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
            srv = &shm->servers[i];
            if (!srv->in_use) { continue; }
            ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z",
                         srv->port);
            for (r = 0; r < XROOTD_CACHE_REAP_REASON_COUNT; r++) {
                mw_printf(mw,
                    "xrootd_cache_dirty_reaped_total"
                    "{port=\"%s\",auth=\"%s\",reason=\"%s\"} %lu\n",
                    port_str, srv->auth, reap_reason[r],
                    (unsigned long) ngx_atomic_fetch_add(
                        &srv->cache_dirty_reaped[r], 0));
            }
        }
    }

    /* WRITE-THROUGH families: dirty-handle/flush-pending gauges and flush
     * counters. NOTE the gate is in_use ONLY (no cache_enabled): write-through
     * mirroring to origin is independent of the read-through cache feature, so
     * these are reported for every active server, cached or not. */
    mw_printf(mw,
        "# HELP xrootd_wt_dirty_handles "
            "Open write-through handles with unflushed dirty data.\n"
        "# TYPE xrootd_wt_dirty_handles gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_wt_dirty_handles{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->wt_dirty_handles, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_wt_flush_pending "
            "Write-through flush tasks currently pending completion.\n"
        "# TYPE xrootd_wt_flush_pending gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_wt_flush_pending{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->wt_flush_pending, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_wt_flushes_total "
            "Write-through flush completions by result.\n"
        "# TYPE xrootd_wt_flushes_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_wt_flushes_total{port=\"%s\",auth=\"%s\",result=\"success\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->wt_flush_success_total, 0));
        mw_printf(mw,
            "xrootd_wt_flushes_total{port=\"%s\",auth=\"%s\",result=\"error\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->wt_flush_error_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_wt_flush_bytes_total "
            "Bytes mirrored to origin by successful write-through flushes.\n"
        "# TYPE xrootd_wt_flush_bytes_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_wt_flush_bytes_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->wt_flush_bytes_total, 0));
    }
}
