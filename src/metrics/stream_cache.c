#include "metrics_internal.h"
#include "../compat/fs_usage.h"

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

void
xrootd_export_stream_cache_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm)
{
    ngx_xrootd_srv_metrics_t *srv;
    ngx_uint_t                i;
    char                      port_str[16];

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
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_occupancy_ratio{port=\"%s\",auth=\"%s\"} %0.6f\n",
            port_str, srv->auth, (double) occupancy_ppm / 1000000.0);
    }

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
