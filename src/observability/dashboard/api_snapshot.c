/*
 * api_snapshot.c - extracted concern
 * Phase-38 split of api.c; behavior-identical.
 */
#include "dashboard_api_internal.h"
#include "fs/vfs/vfs_backend_registry.h"   /* export census for "storage" */


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
dashboard_collect_totals(brix_dashboard_totals_t *totals)
{
    ngx_brix_metrics_t *met;
    ngx_uint_t            srv, i, j;

    ngx_memzero(totals, sizeof(*totals));

    if (ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        return;
    }

    met = ngx_brix_shm_zone->data;
    /* Per-listener slots: connection + byte counters, and stream op errors. */
    for (srv = 0; srv < BRIX_METRICS_MAX_SERVERS; srv++) {
        totals->conn_active += (uint64_t) met->servers[srv].connections_active;
        totals->conn_total  += (uint64_t) met->servers[srv].connections_total;
        totals->bytes_rx    += (uint64_t) met->servers[srv].bytes_rx_total;
        totals->bytes_tx    += (uint64_t) met->servers[srv].bytes_tx_total;
        for (i = 0; i < BRIX_NOPS; i++) {
            totals->stream_errors += (uint64_t) met->servers[srv].op_err[i];
        }
    }

    /* Per-protocol sources stay explicit: each plane's SHM family is
     * heterogeneous by design (proto_list.h checklist step 3). Indices
     * come from the central list; JSON keys generate from it. */
    totals->proto_rx[BRIX_XFER_PROTO_WEBDAV - 1] =
        (uint64_t) met->webdav.bytes_rx_total;
    totals->proto_tx[BRIX_XFER_PROTO_WEBDAV - 1] =
        (uint64_t) met->webdav.bytes_tx_total;
    totals->proto_rx[BRIX_XFER_PROTO_S3 - 1] =
        (uint64_t) met->s3.bytes_rx_total;
    totals->proto_tx[BRIX_XFER_PROTO_S3 - 1] =
        (uint64_t) met->s3.bytes_tx_total;
    /* cvmfs is a read-only site cache: clients never upload, so "in" is the
     * WAN-side origin pull (Stratum-1 fills) and "out" is the LAN-side bytes
     * served (cache hits + fresh fills). */
    totals->proto_rx[BRIX_XFER_PROTO_CVMFS - 1] =
        (uint64_t) met->cvmfs.origin_bytes_total;
    totals->proto_tx[BRIX_XFER_PROTO_CVMFS - 1] =
        (uint64_t) met->cvmfs.bytes_served_hit_total
        + (uint64_t) met->cvmfs.bytes_served_fill_total;
    totals->proto_errors[BRIX_XFER_PROTO_CVMFS - 1] =
        (uint64_t) met->cvmfs.fill_failures_total
        + (uint64_t) met->cvmfs.verify_failures_total;

    /* HTTP error totals = count of all 4xx and 5xx responses, summed over every
     * method. responses_total is indexed [method][status-class]. */
    for (i = 0; i < BRIX_WEBDAV_NMETHODS; i++) {
        totals->proto_errors[BRIX_XFER_PROTO_WEBDAV - 1] +=
            (uint64_t) met->webdav.responses_total[i][BRIX_HTTP_STATUS_4XX]
            + (uint64_t) met->webdav.responses_total[i][BRIX_HTTP_STATUS_5XX];
    }

    for (i = 0; i < BRIX_S3_NMETHODS; i++) {
        for (j = BRIX_HTTP_STATUS_4XX; j <= BRIX_HTTP_STATUS_5XX; j++) {
            totals->proto_errors[BRIX_XFER_PROTO_S3 - 1] +=
                (uint64_t) met->s3.responses_total[i][j];
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
dashboard_collect_protocols(brix_dashboard_protocols_t *out, int64_t now_ms)
{
    brix_transfer_table_t *tbl;
    ngx_uint_t               i;

    ngx_memzero(out, sizeof(*out));

    if (ngx_brix_dashboard_shm_zone == NULL
        || ngx_brix_dashboard_shm_zone->data == NULL
        || ngx_brix_dashboard_shm_zone->data == (void *) 1)
    {
        return;
    }

    tbl = ngx_brix_dashboard_shm_zone->data;
    for (i = 0; i < BRIX_DASHBOARD_MAX_TRANSFERS; i++) {
        brix_transfer_slot_t           *slot = &tbl->slots[i];
        brix_dashboard_proto_summary_t *summary;
        uint64_t                          avg_bps;

        if (slot->in_use == 0) { continue; }

        if (slot->direction == BRIX_XFER_DIR_TPC) {
            summary = &out->tpc;
        } else if (slot->proto >= 1 && slot->proto <= BRIX_XFER_NPROTOS) {
            summary = &out->per[slot->proto - 1];
        } else {
            summary = &out->per[BRIX_XFER_PROTO_ROOT - 1];
        }

        summary->active++;
        avg_bps = dashboard_avg_bps((int64_t) slot->bytes, slot->start_ms, now_ms);
        if (slot->direction == BRIX_XFER_DIR_WRITE) {
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
dashboard_build_limits(const ngx_http_brix_dashboard_loc_conf_t *conf)
{
    json_t *obj = json_object();
    if (!obj) { return NULL; }
    json_object_set_new(obj, "max_active_transfers",       json_integer(BRIX_DASHBOARD_MAX_TRANSFERS));
    json_object_set_new(obj, "max_tpc_registry_transfers", json_integer(BRIX_TPC_REGISTRY_SLOTS));
    json_object_set_new(obj, "max_tpc_transfer_rows",      json_integer(TPC_REGISTRY_JSON_LIMIT));
    json_object_set_new(obj, "max_recent_events",          json_integer(BRIX_DASHBOARD_MAX_EVENTS));
    json_object_set_new(obj, "history_bucket_seconds",     json_integer(BRIX_DASHBOARD_HISTORY_INTERVAL_MS / 1000));
    json_object_set_new(obj, "idle_threshold_ms",          json_integer((json_int_t) conf->idle_threshold_ms));
    json_object_set_new(obj, "stalled_threshold_ms",       json_integer((json_int_t) conf->stalled_threshold_ms));
    return obj;
}


json_t *
dashboard_build_totals(const brix_dashboard_totals_t *totals)
{
    json_t *obj = json_object();
    if (!obj) { return NULL; }
    json_object_set_new(obj, "connections_active",  json_integer((json_int_t) totals->conn_active));
    json_object_set_new(obj, "connections_total",   json_integer((json_int_t) totals->conn_total));
    json_object_set_new(obj, "bytes_rx_total",      json_integer((json_int_t) totals->bytes_rx));
    json_object_set_new(obj, "bytes_tx_total",      json_integer((json_int_t) totals->bytes_tx));
    /* Per-HTTP-protocol keys generate from the central list (dash_name):
     * "webdav_bytes_rx", "s3_errors_total", ... — byte-identical to the
     * historic hand-written keys. The stream plane keeps its historic
     * global keys (bytes_rx_total / stream_errors_total) above. */
    {
        static const char *names[BRIX_XFER_NPROTOS] = {
#define X(ID, metric_label, dash_name, http_plane) dash_name,
            BRIX_PROTO_LIST(X)
#undef X
        };
        static const unsigned http_plane[BRIX_XFER_NPROTOS] = {
#define X(ID, metric_label, dash_name, http_plane) http_plane,
            BRIX_PROTO_LIST(X)
#undef X
        };
        char        key[64];
        ngx_uint_t  p;

        for (p = 0; p < BRIX_XFER_NPROTOS; p++) {
            if (!http_plane[p]) {
                continue;
            }
            ngx_snprintf((u_char *) key, sizeof(key), "%s_bytes_rx%Z",
                         names[p]);
            json_object_set_new(obj, key,
                json_integer((json_int_t) totals->proto_rx[p]));
            ngx_snprintf((u_char *) key, sizeof(key), "%s_bytes_tx%Z",
                         names[p]);
            json_object_set_new(obj, key,
                json_integer((json_int_t) totals->proto_tx[p]));
        }
        json_object_set_new(obj, "stream_errors_total",
            json_integer((json_int_t) totals->stream_errors));
        for (p = 0; p < BRIX_XFER_NPROTOS; p++) {
            if (!http_plane[p]) {
                continue;
            }
            ngx_snprintf((u_char *) key, sizeof(key), "%s_errors_total%Z",
                         names[p]);
            json_object_set_new(obj, key,
                json_integer((json_int_t) totals->proto_errors[p]));
        }
    }
    return obj;
}


json_t *
dashboard_build_proto_summary(const brix_dashboard_proto_summary_t *s,
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
    const brix_dashboard_totals_t *totals)
{
    brix_dashboard_protocols_t ps;
    json_t *obj, *tpc_obj;

    dashboard_collect_protocols(&ps, now_ms);

    obj = json_object();
    if (!obj) { return NULL; }

    /* One summary per protocol, keys from the central list. The stream
     * plane pairs the GLOBAL byte counters (its historic shape); HTTP
     * planes pair their per-proto totals. */
    {
        ngx_uint_t p;

        for (p = 0; p < BRIX_XFER_NPROTOS; p++) {
            uint64_t rx = (p == BRIX_XFER_PROTO_ROOT - 1)
                        ? totals->bytes_rx : totals->proto_rx[p];
            uint64_t tx = (p == BRIX_XFER_PROTO_ROOT - 1)
                        ? totals->bytes_tx : totals->proto_tx[p];

            json_object_set_new(obj, dashboard_proto_name((uint8_t)(p + 1)),
                dashboard_build_proto_summary(&ps.per[p], rx, tx));
        }
    }

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
    brix_dashboard_event_t *events;
    ngx_uint_t                n, i;
    json_t                   *arr;

    arr = json_array();
    if (!arr) { return NULL; }

    events = ngx_pcalloc(pool, sizeof(*events) * BRIX_DASHBOARD_MAX_EVENTS);
    if (events == NULL) { return arr; }

    n = brix_dashboard_events_snapshot(events, BRIX_DASHBOARD_MAX_EVENTS);
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
    brix_dashboard_history_bucket_t *buckets;
    ngx_uint_t                         n, i;
    json_t                            *arr;

    json_object_set_new(target, "bucket_seconds",
                        json_integer(BRIX_DASHBOARD_HISTORY_INTERVAL_MS / 1000));

    arr = json_array();
    buckets = ngx_pcalloc(pool,
                          sizeof(*buckets) * BRIX_DASHBOARD_HISTORY_BUCKETS);
    if (buckets == NULL || arr == NULL) {
        json_object_set_new(target, "buckets", arr ? arr : json_array());
        return;
    }

    n = brix_dashboard_history_snapshot(buckets,
                                          BRIX_DASHBOARD_HISTORY_BUCKETS);
    for (i = 0; i < n; i++) {
        json_t *b = json_object();
        if (!b) { continue; }
        json_object_set_new(b, "time_ms",             json_integer((json_int_t) buckets[i].bucket_start_ms));
        {
            char        akey[48];
            ngx_uint_t  p;

            for (p = 0; p < BRIX_XFER_NPROTOS; p++) {
                ngx_snprintf((u_char *) akey, sizeof(akey), "active_%s%Z",
                             dashboard_proto_name((uint8_t)(p + 1)));
                json_object_set_new(b, akey,
                    json_integer((json_int_t) buckets[i].active[p]));
            }
        }
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
    ngx_brix_metrics_t *met;
    ngx_uint_t            i;
    ngx_uint_t            enabled = 0;
    uint64_t              wt_dirty = 0, wt_pending = 0;
    uint64_t              wt_success = 0, wt_errors = 0, wt_bytes = 0;
    json_t               *listeners, *wt;

    if (ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
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

    met = ngx_brix_shm_zone->data;
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        if (met->servers[i].in_use && met->servers[i].cache_enabled) { enabled = 1; }
        wt_dirty   += (uint64_t) met->servers[i].wt_dirty_handles;
        wt_pending += (uint64_t) met->servers[i].wt_flush_pending;
        wt_success += (uint64_t) met->servers[i].wt_flush_success_total;
        wt_errors  += (uint64_t) met->servers[i].wt_flush_error_total;
        wt_bytes   += (uint64_t) met->servers[i].wt_flush_bytes_total;
    }

    listeners = json_array();
    if (listeners) {
        for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
            ngx_brix_srv_metrics_t *srv = &met->servers[i];
            brix_fs_usage_t         fsu;
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

            if (brix_fs_usage_stat(srv->cache_root, &fsu) == NGX_OK) {
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
 * dashboard_fill_storage — adds "exports" (per-export backend identity plus
 * live-statvfs capacity for local backends) and "io" (per-backend byte
 * totals) to `target`. The identity source is the config-time VFS backend
 * registry (the same census behind /vfs and the storage-backend info gauge),
 * so it covers stream AND http exports. redact (anonymous tier) omits the
 * export root and origin host — numbers only, matching the cache panel.
 */
static void
dashboard_fill_storage(json_t *target, ngx_uint_t redact)
{
    ngx_uint_t  i, n;
    json_t     *exports, *io;

    exports = json_array();
    if (exports != NULL) {
        n = brix_vfs_backend_export_count();
        for (i = 0; i < n; i++) {
            brix_vfs_backend_info_t info;
            brix_fs_usage_t         fsu;
            json_t                   *e;
            int                       local;

            if (brix_vfs_backend_export_info(i, &info) != NGX_OK) {
                continue;
            }
            e = json_object();
            if (e == NULL) {
                continue;
            }
            local = ngx_strcmp(info.backend, "posix") == 0
                    || ngx_strcmp(info.backend, "pblock") == 0;

            json_object_set_new(e, "backend", json_string(info.backend));
            json_object_set_new(e, "remote",  local ? json_false() : json_true());
            json_object_set_new(e, "staging",
                info.staging ? json_true() : json_false());
            if (!redact) {   /* export path + upstream host are infra detail */
                json_object_set_new(e, "root", json_string(info.root_canon));
                if (info.host != NULL && info.host[0] != '\0') {
                    json_object_set_new(e, "origin_host", json_string(info.host));
                    json_object_set_new(e, "origin_port",
                        json_integer((json_int_t) info.port));
                }
            }
            if (local
                && brix_fs_usage_stat(info.root_canon, &fsu) == NGX_OK)
            {
                json_object_set_new(e, "bytes_total",
                    json_integer((json_int_t) fsu.total_bytes));
                json_object_set_new(e, "bytes_used",
                    json_integer((json_int_t) fsu.occupancy_bytes));
                json_object_set_new(e, "bytes_available",
                    json_integer((json_int_t) fsu.available_bytes));
                json_object_set_new(e, "occupancy_ratio",
                    json_real((double) fsu.occupancy_ppm / 1000000.0));
            }
            json_array_append_new(exports, e);
        }
        json_object_set_new(target, "exports", exports);
    }

    io = json_object();
    if (io != NULL) {
        if (ngx_brix_shm_zone != NULL
            && ngx_brix_shm_zone->data != NULL
            && ngx_brix_shm_zone->data != (void *) 1)
        {
            ngx_brix_metrics_t *met = ngx_brix_shm_zone->data;
            int                   id;

            for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
                uint64_t rd = (uint64_t) met->unified.io_bytes_read_backend[id];
                uint64_t wr = (uint64_t) met->unified.io_bytes_written_backend[id];
                json_t  *b;

                if (rd == 0 && wr == 0) {
                    continue;           /* idle backends stay out of the JSON */
                }
                b = json_object();
                if (b == NULL) {
                    continue;
                }
                json_object_set_new(b, "bytes_read_total",
                    json_integer((json_int_t) rd));
                json_object_set_new(b, "bytes_written_total",
                    json_integer((json_int_t) wr));
                json_object_set_new(io, brix_fs_id_name(id), b);
            }
        }
        json_object_set_new(target, "io", io);
    }
}


/*
 * dashboard_fill_cluster — adds "stale_after_ms" and "servers" directly to
 * `target`.  Called with target=root for v1/cluster and target=sub-object for
 * snapshot.
 */
void
dashboard_fill_cluster(json_t *target, ngx_pool_t *pool, int64_t now_ms,
    const ngx_http_brix_dashboard_loc_conf_t *conf, ngx_uint_t redact)
{
    brix_srv_snapshot_entry_t *entries;
    ngx_uint_t                   n, i;
    json_t                      *servers;

    json_object_set_new(target, "stale_after_ms",
                        json_integer((json_int_t) conf->cluster_stale_after_ms));

    servers = json_array();
    entries = ngx_pcalloc(pool, sizeof(*entries) * BRIX_SRV_REGISTRY_SLOTS);
    if (entries == NULL || servers == NULL) {
        json_object_set_new(target, "servers", servers ? servers : json_array());
        return;
    }

    n = brix_srv_snapshot(entries, BRIX_SRV_REGISTRY_SLOTS,
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
    const ngx_http_brix_dashboard_loc_conf_t *conf)
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
    int64_t now_ms, const ngx_http_brix_dashboard_loc_conf_t *conf,
    const brix_dashboard_totals_t *totals, ngx_uint_t redact)
{
    json_t *root, *history, *cache, *storage, *cluster, *cvmfs;

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

    storage = json_object();
    if (storage) {
        dashboard_fill_storage(storage, redact);
        json_object_set_new(root, "storage", storage);
    }

    cluster = json_object();
    if (cluster) {
        dashboard_fill_cluster(cluster, r->pool, now_ms, conf, redact);
        json_object_set_new(root, "cluster", cluster);
    }

    cvmfs = json_object();
    if (cvmfs) {
        dashboard_fill_cvmfs(cvmfs, redact);
        json_object_set_new(root, "cvmfs", cvmfs);
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
    int64_t now_ms, const ngx_http_brix_dashboard_loc_conf_t *conf,
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
    int64_t now_ms, const ngx_http_brix_dashboard_loc_conf_t *conf,
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
    int64_t now_ms, const ngx_http_brix_dashboard_loc_conf_t *conf,
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
    const ngx_http_brix_dashboard_loc_conf_t *conf, ngx_uint_t redact)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous", redact ? json_true() : json_false());
    dashboard_fill_cache(root, redact);
    return root;
}
