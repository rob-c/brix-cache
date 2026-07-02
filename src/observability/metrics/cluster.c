/*
 * metrics/cluster.c — Prometheus gauges for the shared-memory server registry.
 *
 * Exports per-server free-space, utilisation, heartbeat age, and blacklist
 * status so operators can monitor cluster membership without polling the
 * dashboard API.  Unlike other metrics files this one reads directly from the
 * registry SHM zone (via xrootd_srv_snapshot) rather than from the stream
 * module's per-worker metrics zone.
 */

#include "metrics_internal.h"
#include "metrics_macros.h"
#include "net/manager/registry.h"

/*
 * WHAT: emit the per-server cluster gauges and aggregate health-check counters
 *       into the supplied metrics writer.
 * WHY: operators need live visibility into registry membership (which data
 *      servers the manager knows about, their reported space/load, heartbeat
 *      freshness, and blacklist state) without scraping the dashboard JSON API.
 * HOW: take a point-in-time copy of the registry SHM via xrootd_srv_snapshot()
 *      (which acquires the registry spinlock, copies under lock, and releases —
 *      so everything below operates on the local stack array `entries` and
 *      holds no lock), then walk that copy once per metric family.  Each family
 *      is its own emit loop so the HELP/TYPE banner is written exactly once
 *      ahead of the per-server samples (Prometheus requires the banner before
 *      any sample of that family).
 */
void
xrootd_export_cluster_metrics(metrics_writer_t *mw)
{
    /* Stack snapshot buffer; sized to the compile-time slot maximum so a full
     * registry always fits without a heap allocation in the scrape path. */
    xrootd_srv_snapshot_entry_t  entries[XROOTD_SRV_REGISTRY_SLOTS];
    ngx_uint_t                   n, i;
    ngx_msec_t                   now;
    /* 255 (max host) + 1 (':') + 5 (port digits) + 1 ('\0') = 262; use 512. */
    char                         srv_label[512];

    /* Registry SHM is only created in manager/redirector mode; with no zone
     * there is no cluster to report — emit nothing (not even the count gauge). */
    if (xrootd_srv_shm_zone == NULL) {
        return;
    }

    /* Sample the clock once so the heartbeat-age and blacklist comparisons
     * below all reference the same instant as the snapshot was taken. */
    now = ngx_current_msec;
    n   = xrootd_srv_snapshot(entries, XROOTD_SRV_REGISTRY_SLOTS, now);

    mw_printf(mw,
        "# HELP xrootd_cluster_servers_registered "
            "Number of data servers currently in the cluster registry.\n"
        "# TYPE xrootd_cluster_servers_registered gauge\n"
        "xrootd_cluster_servers_registered %u\n",
        (unsigned int) n);

    /* Count gauge already emitted; with no occupied slots there are no
     * per-server families to follow, so stop before the emit loops. */
    if (n == 0) {
        return;
    }

    /* Build the {server="host:port"} label into the shared srv_label buffer.
     * %.255s bounds the host copy to the registry's host[256] field width so a
     * non-NUL-terminated or oversized host can never overrun srv_label[512].
     * Re-invoked at the top of every emit loop because the buffer is reused. */
#define CLUSTER_LABEL(idx) \
    snprintf(srv_label, sizeof(srv_label), "%.255s:%u", \
             entries[(idx)].host, (unsigned int) entries[(idx)].port)

    mw_printf(mw,
        "# HELP xrootd_cluster_server_free_megabytes "
            "Free disk space (MB) last reported by each registered data server.\n"
        "# TYPE xrootd_cluster_server_free_megabytes gauge\n");
    for (i = 0; i < n; i++) {
        CLUSTER_LABEL(i);
        mw_printf(mw,
            "xrootd_cluster_server_free_megabytes{server=\"%s\"} %u\n",
            srv_label, (unsigned int) entries[i].free_mb);
    }

    mw_printf(mw,
        "# HELP xrootd_cluster_server_utilization_percent "
            "Storage utilisation percent (0-100) last reported by each data server.\n"
        "# TYPE xrootd_cluster_server_utilization_percent gauge\n");
    for (i = 0; i < n; i++) {
        CLUSTER_LABEL(i);
        mw_printf(mw,
            "xrootd_cluster_server_utilization_percent{server=\"%s\"} %u\n",
            srv_label, (unsigned int) entries[i].util_pct);
    }

    mw_printf(mw,
        "# HELP xrootd_cluster_server_last_seen_seconds "
            "Seconds since this data server last sent a CMS heartbeat to the manager.\n"
        "# TYPE xrootd_cluster_server_last_seen_seconds gauge\n");
    for (i = 0; i < n; i++) {
        /* last_seen is the ngx_current_msec captured at the server's last
         * heartbeat; age is now - last_seen converted ms -> s.  The (now >=
         * last_seen) guard avoids an unsigned underflow producing a huge bogus
         * age if last_seen is momentarily ahead of `now` (clock skew between
         * the worker that recorded it and this scrape) — clamp to 0 instead. */
        double age_s = (now >= entries[i].last_seen)
                       ? (double)(now - entries[i].last_seen) / 1000.0
                       : 0.0;
        CLUSTER_LABEL(i);
        mw_printf(mw,
            "xrootd_cluster_server_last_seen_seconds{server=\"%s\"} %.3f\n",
            srv_label, age_s);
    }

    mw_printf(mw,
        "# HELP xrootd_cluster_server_blacklisted "
            "1 if the server is temporarily blacklisted after a CMS disconnect, "
            "0 if available.\n"
        "# TYPE xrootd_cluster_server_blacklisted gauge\n");
    for (i = 0; i < n; i++) {
        /* blacklisted_until==0 means "available"; any non-zero value is a
         * future ngx_current_msec deadline.  The entry is still blacklisted
         * only while that deadline is in the future (> now); a deadline that
         * has already elapsed reports 0 even though the registry hasn't yet
         * lazily cleared the field. */
        int bl = (entries[i].blacklisted_until != 0
                  && entries[i].blacklisted_until > now) ? 1 : 0;
        CLUSTER_LABEL(i);
        mw_printf(mw,
            "xrootd_cluster_server_blacklisted{server=\"%s\"} %d\n",
            srv_label, bl);
    }

    /* error_count doubles as the cumulative CMS-disconnect counter for the
     * entry; exposed as a Prometheus counter (monotonic within a slot's life,
     * but resets if the slot is recycled to a different server). */
    mw_printf(mw,
        "# HELP xrootd_cluster_server_disconnect_total "
            "Cumulative CMS disconnect count for each registered data server.\n"
        "# TYPE xrootd_cluster_server_disconnect_total counter\n");
    for (i = 0; i < n; i++) {
        CLUSTER_LABEL(i);
        mw_printf(mw,
            "xrootd_cluster_server_disconnect_total{server=\"%s\"} %u\n",
            srv_label, (unsigned int) entries[i].error_count);
    }

#undef CLUSTER_LABEL

    /* Phase 22 — aggregate health-check counters (no per-server labels, per
     * INVARIANT 8: low-cardinality only; per-server HC state is on the
     * dashboard snapshot API). */
    {
        /* These four counters live in the stream module's shared metrics zone
         * (not the registry SHM walked above), so fetch that mapping separately;
         * it is NULL until the metrics zone is initialised. */
        ngx_xrootd_metrics_t *m = xrootd_metrics_shared();
        if (m != NULL) {
            mw_printf(mw,
                "# HELP xrootd_cluster_hc_probes_total "
                    "Active health-check probes started.\n"
                "# TYPE xrootd_cluster_hc_probes_total counter\n"
                "xrootd_cluster_hc_probes_total %lu\n"
                "# HELP xrootd_cluster_hc_pass_total "
                    "Health-check probes that passed.\n"
                "# TYPE xrootd_cluster_hc_pass_total counter\n"
                "xrootd_cluster_hc_pass_total %lu\n"
                "# HELP xrootd_cluster_hc_fail_total "
                    "Health-check probes that failed or timed out.\n"
                "# TYPE xrootd_cluster_hc_fail_total counter\n"
                "xrootd_cluster_hc_fail_total %lu\n"
                "# HELP xrootd_cluster_hc_blacklist_total "
                    "Servers blacklisted by health checking.\n"
                "# TYPE xrootd_cluster_hc_blacklist_total counter\n"
                "xrootd_cluster_hc_blacklist_total %lu\n",
                /* fetch_add(&x, 0) is the lock-free idiom for an atomic READ of
                 * an ngx_atomic_t — adding zero leaves the value unchanged while
                 * returning a consistent snapshot without taking a lock. */
                (unsigned long) ngx_atomic_fetch_add(&m->hc_probes_total, 0),
                (unsigned long) ngx_atomic_fetch_add(&m->hc_pass_total, 0),
                (unsigned long) ngx_atomic_fetch_add(&m->hc_fail_total, 0),
                (unsigned long) ngx_atomic_fetch_add(&m->hc_blacklist_total, 0));
        }
    }
}
