/*
 * WHAT: Export stream-side user identity and VO (virtual organisation) tracking
 *       metrics to Prometheus text exposition format.
 *
 * WHY: XRootD sessions carry VOMS attributes (VO membership) and user identities
 *      (DN or token sub). Tracking these per-session allows operators to see which
 *      VO groups consume most bandwidth, how many unique users connect over time,
 *      and whether the bounded tracking tables are overflowing. Unlike request-level
 *      metrics this is a gauge-style view of active session identity distribution.
 *
 * HOW: Iterates two bounded LRU tables in shared memory (vo_global + user_tracking)
 *      using atomic fetch-add(0) for lock-free reads. Emit four metric families:
 *      1) xrootd_vo_bytes_tx/rx_total — per-VO byte counters (counter)
 *      2) xrootd_vo_requests_total — per-VO request count (counter)
 *      3) xrootd_vo_overflow_total — evicted VO entries since process start (counter)
 *      4) xrootd_unique_users_current/gauge + total/counter + evictions/counter
 *         — active users, lifetime users, and LRU eviction count (gauge + counter)
 *      5) xrootd_user_sessions_total{hash} — session count per hashed user ID (gauge)
 *      VO names truncated to XROOTD_VO_NAME_LEN characters; users identified by
 *      FNV-1a hash of DN or token sub. Empty slots are skipped.
 */

#include "metrics_internal.h"

void
xrootd_export_stream_tracking_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm)
{
    ngx_uint_t  i;

    mw_printf(mw,
        "# HELP xrootd_vo_bytes_tx_total "
            "Bytes sent to clients grouped by virtual organisation. "
            "VO names are truncated to %d characters; the metric family has one entry per VO.\n"
        "# TYPE xrootd_vo_bytes_tx_total counter\n", XROOTD_VO_NAME_LEN - 1);
    for (i = 0; i < XROOTD_VO_MAX_TRACKED; i++) {
        ngx_xrootd_vo_slot_t *vo = &shm->vo_global.slots[i];
        if (!vo->name[0]) { continue; }
        mw_printf(mw, "xrootd_vo_bytes_tx_total{vo=\"%s\"} %lu\n",
                  vo->name, (unsigned long) ngx_atomic_fetch_add(&vo->bytes_tx_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_vo_bytes_rx_total "
            "Bytes received from clients grouped by virtual organisation. "
            "VO names are truncated to %d characters.\n"
        "# TYPE xrootd_vo_bytes_rx_total counter\n", XROOTD_VO_NAME_LEN - 1);
    for (i = 0; i < XROOTD_VO_MAX_TRACKED; i++) {
        ngx_xrootd_vo_slot_t *vo = &shm->vo_global.slots[i];
        if (!vo->name[0]) { continue; }
        mw_printf(mw, "xrootd_vo_bytes_rx_total{vo=\"%s\"} %lu\n",
                  vo->name, (unsigned long) ngx_atomic_fetch_add(&vo->bytes_rx_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_vo_requests_total "
            "Requests grouped by virtual organisation. VO names are truncated.\n"
        "# TYPE xrootd_vo_requests_total counter\n");
    for (i = 0; i < XROOTD_VO_MAX_TRACKED; i++) {
        ngx_xrootd_vo_slot_t *vo = &shm->vo_global.slots[i];
        if (!vo->name[0]) { continue; }
        mw_printf(mw, "xrootd_vo_requests_total{vo=\"%s\"} %lu\n",
                  vo->name, (unsigned long) ngx_atomic_fetch_add(&vo->requests_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_vo_overflow_total "
            "VO entries that exceeded the tracking limit and were evicted.\n"
        "# TYPE xrootd_vo_overflow_total counter\n");
    mw_printf(mw, "xrootd_vo_overflow_total %lu\n",
              (unsigned long) ngx_atomic_fetch_add(&shm->vo_global.overflow_total, 0));

    mw_printf(mw,
        "# HELP xrootd_unique_users_current "
            "Currently tracked unique user identities (bounded LRU, max %d). "
            "Users are identified by DN or token sub via FNV-1a hash.\n"
        "# TYPE xrootd_unique_users_current gauge\n", XROOTD_USERS_MAX_TRACKED);
    mw_printf(mw, "xrootd_unique_users_current %lu\n",
              (unsigned long) ngx_atomic_fetch_add(&shm->user_tracking.unique_count, 0));

    mw_printf(mw,
        "# HELP xrootd_unique_users_total "
            "Lifetime unique user identities seen since process start. "
            "Never decremented.\n"
        "# TYPE xrootd_unique_users_total counter\n");
    mw_printf(mw, "xrootd_unique_users_total %lu\n",
              (unsigned long) ngx_atomic_fetch_add(&shm->user_tracking.total_unique, 0));

    mw_printf(mw,
        "# HELP xrootd_user_evictions_total "
            "User identity slots evicted from the tracking table.\n"
        "# TYPE xrootd_user_evictions_total counter\n");
    mw_printf(mw, "xrootd_user_evictions_total %lu\n",
              (unsigned long) ngx_atomic_fetch_add(&shm->user_tracking.evictions_total, 0));

    mw_printf(mw,
        "# HELP xrootd_user_sessions_total "
            "Sessions per tracked user identity. Sum across all entries equals total authenticated sessions.\n"
        "# TYPE xrootd_user_sessions_total gauge\n");
    for (i = 0; i < XROOTD_USERS_MAX_TRACKED; i++) {
        ngx_xrootd_user_slot_t *u = &shm->user_tracking.slots[i];
        if (!u->id_hash) { continue; }
        mw_printf(mw, "xrootd_user_sessions_total{hash=%08x} %lu\n",
                  u->id_hash, (unsigned long) ngx_atomic_fetch_add(&u->sessions_total, 0));
    }
}
