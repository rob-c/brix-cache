/*
 * api_snapshot.c - extracted concern
 * Phase-38 split of api.c; behavior-identical.
 */
#include "dashboard_api_internal.h"


/*
 * WHAT: Sum the cluster-wide metric counters from the metrics SHM zone into a
 *       single stack struct for the caller to serialise.
 * WHY:  The SHM holds per-listener server slots plus per-protocol blocks; the
 *       dashboard "totals" view aggregates them. Errors are the sum of all
 *       per-op error counters (stream) and 4xx+5xx response counters (HTTP/S3).
 * HOW:  The "(void *) 1" sentinel is nginx's marker for a shm zone that has been
 *       declared but not yet initialised; treat it (and NULL) as "no data" and
 *       leave totals zeroed.
 */
void
dashboard_collect_totals(xrootd_dashboard_totals_t *totals)
{
    ngx_xrootd_metrics_t *met;
    ngx_uint_t            srv, i, j;

    ngx_memzero(totals, sizeof(*totals));

    if (ngx_xrootd_shm_zone == NULL
        || ngx_xrootd_shm_zone->data == NULL
        || ngx_xrootd_shm_zone->data == (void *) 1)
    {
        return;
    }

    met = ngx_xrootd_shm_zone->data;
    /* Per-listener slots: connection + byte counters, and stream op errors. */
    for (srv = 0; srv < XROOTD_METRICS_MAX_SERVERS; srv++) {
        totals->conn_active += (uint64_t) met->servers[srv].connections_active;
        totals->conn_total  += (uint64_t) met->servers[srv].connections_total;
        totals->bytes_rx    += (uint64_t) met->servers[srv].bytes_rx_total;
        totals->bytes_tx    += (uint64_t) met->servers[srv].bytes_tx_total;
        for (i = 0; i < XROOTD_NOPS; i++) {
            totals->stream_errors += (uint64_t) met->servers[srv].op_err[i];
        }
    }

    totals->wdav_rx = (uint64_t) met->webdav.bytes_rx_total;
    totals->wdav_tx = (uint64_t) met->webdav.bytes_tx_total;
    totals->s3_rx   = (uint64_t) met->s3.bytes_rx_total;
    totals->s3_tx   = (uint64_t) met->s3.bytes_tx_total;
    totals->cvmfs_rx = 0;                     /* read-only protocol */
    totals->cvmfs_tx = (uint64_t) met->cvmfs.bytes_served_hit_total
                     + (uint64_t) met->cvmfs.bytes_served_fill_total;
    totals->cvmfs_errors = (uint64_t) met->cvmfs.fill_failures_total
                         + (uint64_t) met->cvmfs.verify_failures_total;

    /* HTTP error totals = count of all 4xx and 5xx responses, summed over every
     * method. responses_total is indexed [method][status-class]. */
    for (i = 0; i < XROOTD_WEBDAV_NMETHODS; i++) {
        totals->webdav_errors +=
            (uint64_t) met->webdav.responses_total[i][XROOTD_HTTP_STATUS_4XX]
            + (uint64_t) met->webdav.responses_total[i][XROOTD_HTTP_STATUS_5XX];
    }

    for (i = 0; i < XROOTD_S3_NMETHODS; i++) {
        for (j = XROOTD_HTTP_STATUS_4XX; j <= XROOTD_HTTP_STATUS_5XX; j++) {
            totals->s3_errors += (uint64_t) met->s3.responses_total[i][j];
        }
    }
}


/*
 * WHAT: Tally live transfers per protocol bucket (root/webdav/s3/tpc) from the
 *       dashboard transfer table, accumulating active counts and aggregate
 *       ingress/egress bandwidth.
 * HOW:  Each in-use slot is classified — TPC direction wins over protocol so a
 *       TPC transfer lands in the tpc bucket regardless of carrier protocol.
 *       Write transfers count toward ingress, all others toward egress.
 */
void
dashboard_collect_protocols(xrootd_dashboard_protocols_t *out, int64_t now_ms)
{
    xrootd_transfer_table_t *tbl;
    ngx_uint_t               i;

    ngx_memzero(out, sizeof(*out));

    if (ngx_xrootd_dashboard_shm_zone == NULL
        || ngx_xrootd_dashboard_shm_zone->data == NULL
        || ngx_xrootd_dashboard_shm_zone->data == (void *) 1)
    {
        return;
    }

    tbl = ngx_xrootd_dashboard_shm_zone->data;
    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
        xrootd_transfer_slot_t           *slot = &tbl->slots[i];
        xrootd_dashboard_proto_summary_t *summary;
        uint64_t                          avg_bps;

        if (slot->in_use == 0) { continue; }

        if (slot->direction == XROOTD_XFER_DIR_TPC) {
            summary = &out->tpc;
        } else if (slot->proto == XROOTD_XFER_PROTO_WEBDAV) {
            summary = &out->webdav;
        } else if (slot->proto == XROOTD_XFER_PROTO_S3) {
            summary = &out->s3;
        } else if (slot->proto == XROOTD_XFER_PROTO_CVMFS) {
            summary = &out->cvmfs;
        } else {
            summary = &out->root;
        }

        summary->active++;
        avg_bps = dashboard_avg_bps((int64_t) slot->bytes, slot->start_ms, now_ms);
        if (slot->direction == XROOTD_XFER_DIR_WRITE) {
            summary->ingress_bps += avg_bps;
        } else {
            summary->egress_bps += avg_bps;
        }
    }
}


/*
 * Leaf builders — each returns a json_t * owned by the caller.
 * NULL return means OOM; the caller passes it to json_object_set_new which
 * handles NULL gracefully (returns -1, key absent from parent).
 * */

json_t *
dashboard_build_limits(const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *obj = json_object();
    if (!obj) { return NULL; }
    json_object_set_new(obj, "max_active_transfers",       json_integer(XROOTD_DASHBOARD_MAX_TRANSFERS));
    json_object_set_new(obj, "max_tpc_registry_transfers", json_integer(XROOTD_TPC_REGISTRY_SLOTS));
    json_object_set_new(obj, "max_tpc_transfer_rows",      json_integer(TPC_REGISTRY_JSON_LIMIT));
    json_object_set_new(obj, "max_recent_events",          json_integer(XROOTD_DASHBOARD_MAX_EVENTS));
    json_object_set_new(obj, "history_bucket_seconds",     json_integer(XROOTD_DASHBOARD_HISTORY_INTERVAL_MS / 1000));
    json_object_set_new(obj, "idle_threshold_ms",          json_integer((json_int_t) conf->idle_threshold_ms));
    json_object_set_new(obj, "stalled_threshold_ms",       json_integer((json_int_t) conf->stalled_threshold_ms));
    return obj;
}


json_t *
dashboard_build_totals(const xrootd_dashboard_totals_t *totals)
{
    json_t *obj = json_object();
    if (!obj) { return NULL; }
    json_object_set_new(obj, "connections_active",  json_integer((json_int_t) totals->conn_active));
    json_object_set_new(obj, "connections_total",   json_integer((json_int_t) totals->conn_total));
    json_object_set_new(obj, "bytes_rx_total",      json_integer((json_int_t) totals->bytes_rx));
    json_object_set_new(obj, "bytes_tx_total",      json_integer((json_int_t) totals->bytes_tx));
    json_object_set_new(obj, "webdav_bytes_rx",     json_integer((json_int_t) totals->wdav_rx));
    json_object_set_new(obj, "webdav_bytes_tx",     json_integer((json_int_t) totals->wdav_tx));
    json_object_set_new(obj, "s3_bytes_rx",         json_integer((json_int_t) totals->s3_rx));
    json_object_set_new(obj, "s3_bytes_tx",         json_integer((json_int_t) totals->s3_tx));
    json_object_set_new(obj, "cvmfs_bytes_rx",      json_integer((json_int_t) totals->cvmfs_rx));
    json_object_set_new(obj, "cvmfs_bytes_tx",      json_integer((json_int_t) totals->cvmfs_tx));
    json_object_set_new(obj, "stream_errors_total", json_integer((json_int_t) totals->stream_errors));
    json_object_set_new(obj, "webdav_errors_total", json_integer((json_int_t) totals->webdav_errors));
    json_object_set_new(obj, "s3_errors_total",     json_integer((json_int_t) totals->s3_errors));
    json_object_set_new(obj, "cvmfs_errors_total",  json_integer((json_int_t) totals->cvmfs_errors));
    return obj;
}


json_t *
dashboard_build_proto_summary(const xrootd_dashboard_proto_summary_t *s,
    uint64_t bytes_rx, uint64_t bytes_tx)
{
    json_t *obj = json_object();
    if (!obj) { return NULL; }
    json_object_set_new(obj, "active",       json_integer((json_int_t) s->active));
    json_object_set_new(obj, "ingress_bps",  json_integer((json_int_t) s->ingress_bps));
    json_object_set_new(obj, "egress_bps",   json_integer((json_int_t) s->egress_bps));
    if (bytes_rx || bytes_tx) {
        json_object_set_new(obj, "bytes_rx_total", json_integer((json_int_t) bytes_rx));
        json_object_set_new(obj, "bytes_tx_total", json_integer((json_int_t) bytes_tx));
    }
    return obj;
}


json_t *
dashboard_build_protocols(int64_t now_ms,
    const xrootd_dashboard_totals_t *totals)
{
    xrootd_dashboard_protocols_t ps;
    json_t *obj, *tpc_obj;

    dashboard_collect_protocols(&ps, now_ms);

    obj = json_object();
    if (!obj) { return NULL; }

    json_object_set_new(obj, "root",   dashboard_build_proto_summary(&ps.root,  totals->bytes_rx, totals->bytes_tx));
    json_object_set_new(obj, "webdav", dashboard_build_proto_summary(&ps.webdav,totals->wdav_rx,  totals->wdav_tx));
    json_object_set_new(obj, "s3",     dashboard_build_proto_summary(&ps.s3,    totals->s3_rx,    totals->s3_tx));
    json_object_set_new(obj, "cvmfs",  dashboard_build_proto_summary(&ps.cvmfs, totals->cvmfs_rx, totals->cvmfs_tx));

    /* tpc has no cumulative byte counters — build inline */
    tpc_obj = json_object();
    if (tpc_obj) {
        json_object_set_new(tpc_obj, "active",      json_integer((json_int_t) ps.tpc.active));
        json_object_set_new(tpc_obj, "ingress_bps", json_integer((json_int_t) ps.tpc.ingress_bps));
        json_object_set_new(tpc_obj, "egress_bps",  json_integer((json_int_t) ps.tpc.egress_bps));
    }
    json_object_set_new(obj, "tpc", tpc_obj);
    return obj;
}


json_t *
dashboard_build_events(ngx_pool_t *pool, ngx_uint_t redact)
{
    xrootd_dashboard_event_t *events;
    ngx_uint_t                n, i;
    json_t                   *arr;

    arr = json_array();
    if (!arr) { return NULL; }

    events = ngx_pcalloc(pool, sizeof(*events) * XROOTD_DASHBOARD_MAX_EVENTS);
    if (events == NULL) { return arr; }

    n = xrootd_dashboard_events_snapshot(events, XROOTD_DASHBOARD_MAX_EVENTS);
    for (i = 0; i < n; i++) {
        json_t *ev = json_object();
        if (!ev) { continue; }
        json_object_set_new(ev, "sequence",  json_integer((json_int_t) events[i].sequence));
        json_object_set_new(ev, "time_ms",   json_integer((json_int_t) events[i].time_ms));
        json_object_set_new(ev, "class",     json_string(dashboard_event_class_name(events[i].class_id)));
        json_object_set_new(ev, "protocol",  json_string(dashboard_proto_name(events[i].proto)));
        json_object_set_new(ev, "status",    json_integer((json_int_t) events[i].status));
        /* message/path_hint can embed paths/identities — empty for anonymous. */
        json_object_set_new(ev, "message",   json_string(redact ? "" : events[i].message));
        json_object_set_new(ev, "path_hint", json_string(redact ? "" : events[i].path_hint));
        json_array_append_new(arr, ev);
    }
    return arr;
}


/*
 * dashboard_fill_history — adds "bucket_seconds" and "buckets" directly to
 * `target`.  Called with target=root for the v1/history endpoint (flat shape)
 * and with target=sub-object for the snapshot endpoint (nested under "history").
 */
void
dashboard_fill_history(json_t *target, ngx_pool_t *pool)
{
    xrootd_dashboard_history_bucket_t *buckets;
    ngx_uint_t                         n, i;
    json_t                            *arr;

    json_object_set_new(target, "bucket_seconds",
                        json_integer(XROOTD_DASHBOARD_HISTORY_INTERVAL_MS / 1000));

    arr = json_array();
    buckets = ngx_pcalloc(pool,
                          sizeof(*buckets) * XROOTD_DASHBOARD_HISTORY_BUCKETS);
    if (buckets == NULL || arr == NULL) {
        json_object_set_new(target, "buckets", arr ? arr : json_array());
        return;
    }

    n = xrootd_dashboard_history_snapshot(buckets,
                                          XROOTD_DASHBOARD_HISTORY_BUCKETS);
    for (i = 0; i < n; i++) {
        json_t *b = json_object();
        if (!b) { continue; }
        json_object_set_new(b, "time_ms",             json_integer((json_int_t) buckets[i].bucket_start_ms));
        json_object_set_new(b, "active_root",         json_integer((json_int_t) buckets[i].active_root));
        json_object_set_new(b, "active_webdav",       json_integer((json_int_t) buckets[i].active_webdav));
        json_object_set_new(b, "active_s3",           json_integer((json_int_t) buckets[i].active_s3));
        json_object_set_new(b, "active_cvmfs",        json_integer((json_int_t) buckets[i].active_cvmfs));
        json_object_set_new(b, "active_tpc",          json_integer((json_int_t) buckets[i].active_tpc));
        json_object_set_new(b, "bytes_rx",            json_integer((json_int_t) buckets[i].bytes_rx));
        json_object_set_new(b, "bytes_tx",            json_integer((json_int_t) buckets[i].bytes_tx));
        json_object_set_new(b, "errors",              json_integer((json_int_t) buckets[i].errors));
        json_object_set_new(b, "auth_failures",       json_integer((json_int_t) buckets[i].auth_failures));
        json_object_set_new(b, "write_stalls",        json_integer((json_int_t) buckets[i].write_stalls));
        json_object_set_new(b, "cache_occupancy_ppm", json_integer((json_int_t) buckets[i].cache_occupancy_ppm));
        json_array_append_new(arr, b);
    }
    json_object_set_new(target, "buckets", arr);
}


/*
 * dashboard_fill_cache — adds "enabled", "listeners", and "write_through"
 * directly to `target`.  Called with target=root for v1/cache (flat shape)
 * and with target=sub-object for snapshot (nested under "cache").
 */
void
dashboard_fill_cache(json_t *target, ngx_uint_t redact)
{
    ngx_xrootd_metrics_t *met;
    ngx_uint_t            i;
    ngx_uint_t            enabled = 0;
    uint64_t              wt_dirty = 0, wt_pending = 0;
    uint64_t              wt_success = 0, wt_errors = 0, wt_bytes = 0;
    json_t               *listeners, *wt;

    if (ngx_xrootd_shm_zone == NULL
        || ngx_xrootd_shm_zone->data == NULL
        || ngx_xrootd_shm_zone->data == (void *) 1)
    {
        wt = json_object();
        if (wt) {
            json_object_set_new(wt, "enabled",             json_false());
            json_object_set_new(wt, "dirty_handles",       json_integer(0));
            json_object_set_new(wt, "flush_pending",       json_integer(0));
            json_object_set_new(wt, "flush_success_total", json_integer(0));
            json_object_set_new(wt, "flush_errors_total",  json_integer(0));
            json_object_set_new(wt, "flush_bytes_total",   json_integer(0));
        }
        json_object_set_new(target, "enabled",       json_false());
        json_object_set_new(target, "listeners",     json_array());
        json_object_set_new(target, "write_through", wt);
        return;
    }

    met = ngx_xrootd_shm_zone->data;
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        if (met->servers[i].in_use && met->servers[i].cache_enabled) { enabled = 1; }
        wt_dirty   += (uint64_t) met->servers[i].wt_dirty_handles;
        wt_pending += (uint64_t) met->servers[i].wt_flush_pending;
        wt_success += (uint64_t) met->servers[i].wt_flush_success_total;
        wt_errors  += (uint64_t) met->servers[i].wt_flush_error_total;
        wt_bytes   += (uint64_t) met->servers[i].wt_flush_bytes_total;
    }

    listeners = json_array();
    if (listeners) {
        for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
            ngx_xrootd_srv_metrics_t *srv = &met->servers[i];
            xrootd_fs_usage_t         fsu;
            json_t                   *entry;

            if (!srv->in_use || !srv->cache_enabled) { continue; }

            entry = json_object();
            if (!entry) { continue; }
            if (!redact) {   /* listen port is infra detail — omit for anonymous */
                json_object_set_new(entry, "port", json_integer((json_int_t) srv->port));
            }
            json_object_set_new(entry, "auth", json_string(srv->auth));
            /* Ratios are stored in SHM as parts-per-million integers (so the
             * counters stay lock-free); divide by 1e6 to expose a 0..1 float. */
            json_object_set_new(entry, "eviction_threshold_ratio",
                json_real((double) srv->cache_eviction_threshold / 1000000.0));
            json_object_set_new(entry, "evictions_total",
                json_integer((json_int_t) srv->cache_evictions_total));
            json_object_set_new(entry, "evicted_bytes_total",
                json_integer((json_int_t) srv->cache_evicted_bytes_total));
            json_object_set_new(entry, "eviction_errors_total",
                json_integer((json_int_t) srv->cache_eviction_errors_total));

            if (xrootd_fs_usage_stat(srv->cache_root, &fsu) == NGX_OK) {
                json_object_set_new(entry, "occupancy_ratio",
                    json_real((double) fsu.occupancy_ppm / 1000000.0));
                json_object_set_new(entry, "bytes_total",
                    json_integer((json_int_t) fsu.total_bytes));
                json_object_set_new(entry, "bytes_used",
                    json_integer((json_int_t) fsu.occupancy_bytes));
                json_object_set_new(entry, "bytes_available",
                    json_integer((json_int_t) fsu.available_bytes));
            }
            json_array_append_new(listeners, entry);
        }
    }

    wt = json_object();
    if (wt) {
        /* No dedicated "write-through configured" flag exists in SHM, so infer
         * it: write-through is reported enabled if any of its counters are
         * non-zero (i.e. it has done work). */
        json_object_set_new(wt, "enabled",
            (wt_dirty || wt_pending || wt_success || wt_errors || wt_bytes)
            ? json_true() : json_false());
        json_object_set_new(wt, "dirty_handles",       json_integer((json_int_t) wt_dirty));
        json_object_set_new(wt, "flush_pending",       json_integer((json_int_t) wt_pending));
        json_object_set_new(wt, "flush_success_total", json_integer((json_int_t) wt_success));
        json_object_set_new(wt, "flush_errors_total",  json_integer((json_int_t) wt_errors));
        json_object_set_new(wt, "flush_bytes_total",   json_integer((json_int_t) wt_bytes));
    }

    json_object_set_new(target, "enabled",       enabled ? json_true() : json_false());
    json_object_set_new(target, "listeners",     listeners);
    json_object_set_new(target, "write_through", wt);
}


/*
 * dashboard_fill_cluster — adds "stale_after_ms" and "servers" directly to
 * `target`.  Called with target=root for v1/cluster and target=sub-object for
 * snapshot.
 */
void
dashboard_fill_cluster(json_t *target, ngx_pool_t *pool, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact)
{
    xrootd_srv_snapshot_entry_t *entries;
    ngx_uint_t                   n, i;
    json_t                      *servers;

    json_object_set_new(target, "stale_after_ms",
                        json_integer((json_int_t) conf->cluster_stale_after_ms));

    servers = json_array();
    entries = ngx_pcalloc(pool, sizeof(*entries) * XROOTD_SRV_REGISTRY_SLOTS);
    if (entries == NULL || servers == NULL) {
        json_object_set_new(target, "servers", servers ? servers : json_array());
        return;
    }

    n = xrootd_srv_snapshot(entries, XROOTD_SRV_REGISTRY_SLOTS,
                            (ngx_msec_t) now_ms);
    for (i = 0; i < n; i++) {
        int64_t age = now_ms >= (int64_t) entries[i].last_seen
                      ? now_ms - (int64_t) entries[i].last_seen : 0;
        json_t *srv = json_object();
        if (!srv) { continue; }
        json_object_set_new(srv, "host", json_string(redact ? "[redacted]" : entries[i].host));
        if (!redact) {   /* port + exported paths are infra detail for anonymous */
            json_object_set_new(srv, "port",  json_integer((json_int_t) entries[i].port));
            json_object_set_new(srv, "paths", json_string(entries[i].paths));
        }
        json_object_set_new(srv, "free_mb",           json_integer((json_int_t) entries[i].free_mb));
        json_object_set_new(srv, "util_pct",          json_integer((json_int_t) entries[i].util_pct));
        json_object_set_new(srv, "last_seen",         json_integer((json_int_t) entries[i].last_seen));
        json_object_set_new(srv, "heartbeat_age_ms",  json_integer((json_int_t) age));
        json_object_set_new(srv, "stale",
            age > (int64_t) conf->cluster_stale_after_ms ? json_true() : json_false());
        /* Phase 23: a non-zero blacklist means the server is drained/blacklisted. */
        json_object_set_new(srv, "draining",
            entries[i].blacklisted_until != 0 ? json_true() : json_false());
        json_array_append_new(servers, srv);
    }
    json_object_set_new(target, "servers", servers);
}


/*
 * Top-level endpoint builders
 * */

json_t *
dashboard_new_v1_root(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = json_object();
    if (!root) { return NULL; }
    dashboard_json_set_schema(root);
    json_object_set_new(root, "server_ms", json_integer((json_int_t) now_ms));
    json_object_set_new(root, "limits",    dashboard_build_limits(conf));
    return root;
}


json_t *
dashboard_build_v1_snapshot(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const xrootd_dashboard_totals_t *totals, ngx_uint_t redact)
{
    json_t *root, *history, *cache, *cluster;

    root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }

    /* The page JS keys off this flag to render the anonymous banner + hide the
     * (now-redacted) PII columns. */
    json_object_set_new(root, "anonymous",        redact ? json_true() : json_false());
    json_object_set_new(root, "active_transfers", dashboard_build_transfer_rows(now_ms, conf, 1, redact));
    json_object_set_new(root, "tpc_transfers",    dashboard_build_tpc_registry(r->pool, redact));
    json_object_set_new(root, "protocols",        dashboard_build_protocols(now_ms, totals));

    cache = json_object();
    if (cache) {
        dashboard_fill_cache(cache, redact);
        json_object_set_new(root, "cache", cache);
    }

    cluster = json_object();
    if (cluster) {
        dashboard_fill_cluster(cluster, r->pool, now_ms, conf, redact);
        json_object_set_new(root, "cluster", cluster);
    }

    json_object_set_new(root, "events", dashboard_build_events(r->pool, redact));

    history = json_object();
    if (history) {
        dashboard_fill_history(history, r->pool);
        json_object_set_new(root, "history", history);
    }

    json_object_set_new(root, "totals", dashboard_build_totals(totals));
    return root;
}


json_t *
dashboard_build_v1_events(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    ngx_uint_t redact)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous", redact ? json_true() : json_false());
    json_object_set_new(root, "events", dashboard_build_events(r->pool, redact));
    return root;
}


json_t *
dashboard_build_v1_history(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    ngx_uint_t redact)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous", redact ? json_true() : json_false());
    dashboard_fill_history(root, r->pool);   /* history carries no PII */
    return root;
}


json_t *
dashboard_build_v1_cluster(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    ngx_uint_t redact)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous", redact ? json_true() : json_false());
    dashboard_fill_cluster(root, r->pool, now_ms, conf, redact);
    return root;
}


json_t *
dashboard_build_v1_cache(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous", redact ? json_true() : json_false());
    dashboard_fill_cache(root, redact);
    return root;
}
