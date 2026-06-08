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
#include "../manager/registry.h"

void
xrootd_export_cluster_metrics(metrics_writer_t *mw)
{
    xrootd_srv_snapshot_entry_t  entries[XROOTD_SRV_REGISTRY_SLOTS];
    ngx_uint_t                   n, i;
    ngx_msec_t                   now;
    /* 255 (max host) + 1 (':') + 5 (port digits) + 1 ('\0') = 262; use 512. */
    char                         srv_label[512];

    if (xrootd_srv_shm_zone == NULL) {
        return;
    }

    now = ngx_current_msec;
    n   = xrootd_srv_snapshot(entries, XROOTD_SRV_REGISTRY_SLOTS, now);

    mw_printf(mw,
        "# HELP xrootd_cluster_servers_registered "
            "Number of data servers currently in the cluster registry.\n"
        "# TYPE xrootd_cluster_servers_registered gauge\n"
        "xrootd_cluster_servers_registered %u\n",
        (unsigned int) n);

    if (n == 0) {
        return;
    }

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
        int bl = (entries[i].blacklisted_until != 0
                  && entries[i].blacklisted_until > now) ? 1 : 0;
        CLUSTER_LABEL(i);
        mw_printf(mw,
            "xrootd_cluster_server_blacklisted{server=\"%s\"} %d\n",
            srv_label, bl);
    }

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
}
