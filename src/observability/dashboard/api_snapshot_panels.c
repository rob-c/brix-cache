/*
 * api_snapshot_panels.c - snapshot cache / storage / cluster panel builders.
 *
 * WHAT: Owns the three "infrastructure panel" fills of the dashboard snapshot —
 *       "cache" (write-through + per-listener cache stats), "storage" (VFS
 *       export census + per-backend byte I/O), and "cluster" (server registry
 *       heartbeats). Each is a `dashboard_fill_*(json_t *target, ...)` that
 *       populates keys directly on a caller-supplied object.
 * WHY:  Split out of api_snapshot.c (phase-79 file-size split) to keep both
 *       files under the 500-line ceiling. These panels form one cohesive
 *       cluster: they all read the metrics/VFS/registry SHM planes and emit
 *       redact-aware infra detail, distinct from the totals/protocol/event
 *       collectors and the top-level endpoint builders that stay in
 *       api_snapshot.c. Behavior is byte-identical to the pre-split code.
 * HOW:  The cross-file seam lives in dashboard_api_internal.h — dashboard_fill_
 *       cache / _storage / _cluster are the entry points the snapshot and the
 *       flat v1 endpoint builders (in api_snapshot.c) call; every other helper
 *       here is file-static.
 */
#include "dashboard_api_internal.h"
#include "fs/vfs/vfs_backend_registry.h"   /* export census for "storage" */


/*
 * WHAT: Write-through byte/handle counters, summed across all listener slots.
 * WHY:  dashboard_fill_cache reports both the disabled (all-zero) and live
 *       shapes of the write_through object; carrying the tallies in one struct
 *       keeps the sum loop and the JSON builder decoupled.
 */
typedef struct {
    uint64_t dirty;
    uint64_t pending;
    uint64_t success;
    uint64_t errors;
    uint64_t bytes;
} dashboard_wt_totals_t;


/*
 * WHAT: Build the "write_through" JSON object from a set of counter totals.
 * WHY:  Both the no-data path (all zero) and the live path emit an identical
 *       key set; one builder guarantees byte-identical output for either.
 * HOW:  "enabled" is inferred true iff any counter is non-zero (no dedicated
 *       configured-flag lives in SHM). Returns NULL on OOM — the caller passes
 *       that straight to json_object_set_new, which tolerates NULL.
 */
static json_t *
dashboard_build_write_through(const dashboard_wt_totals_t *wt_t)
{
    json_t *wt = json_object();
    if (!wt) { return NULL; }
    json_object_set_new(wt, "enabled",
        (wt_t->dirty || wt_t->pending || wt_t->success
         || wt_t->errors || wt_t->bytes)
        ? json_true() : json_false());
    json_object_set_new(wt, "dirty_handles",       json_integer((json_int_t) wt_t->dirty));
    json_object_set_new(wt, "flush_pending",       json_integer((json_int_t) wt_t->pending));
    json_object_set_new(wt, "flush_success_total", json_integer((json_int_t) wt_t->success));
    json_object_set_new(wt, "flush_errors_total",  json_integer((json_int_t) wt_t->errors));
    json_object_set_new(wt, "flush_bytes_total",   json_integer((json_int_t) wt_t->bytes));
    return wt;
}


/*
 * WHAT: Emit the disabled cache shape (no SHM data) into `target`.
 * WHY:  When the metrics zone is absent the panel still needs a stable
 *       structure: cache disabled, empty listener list, all-zero write-through.
 * HOW:  A zero-initialised totals struct drives the shared write_through
 *       builder so the disabled object is byte-identical to a live-but-idle one.
 */
static void
dashboard_fill_cache_empty(json_t *target)
{
    dashboard_wt_totals_t wt_t = { 0, 0, 0, 0, 0 };

    json_object_set_new(target, "enabled",       json_false());
    json_object_set_new(target, "listeners",     json_array());
    json_object_set_new(target, "write_through", dashboard_build_write_through(&wt_t));
}


/*
 * WHAT: Build the per-listener cache JSON entry for one in-use, cache-enabled
 *       server slot.
 * WHY:  Isolating the entry shape keeps the listener loop flat and lets the
 *       stat/eviction fields live next to their comments.
 * HOW:  Ratios are stored in SHM as parts-per-million integers (lock-free);
 *       divide by 1e6 for a 0..1 float. `redact` drops the listen port (infra
 *       detail) for the anonymous tier. Returns NULL on OOM.
 */
static json_t *
dashboard_build_cache_listener(const ngx_brix_srv_metrics_t *srv,
    ngx_uint_t redact)
{
    brix_fs_usage_t fsu;
    json_t         *entry = json_object();

    if (!entry) { return NULL; }
    if (!redact) {   /* listen port is infra detail — omit for anonymous */
        json_object_set_new(entry, "port", json_integer((json_int_t) srv->port));
    }
    json_object_set_new(entry, "auth", json_string(srv->auth));
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
    return entry;
}


/*
 * WHAT: Build the "listeners" array — one entry per in-use, cache-enabled slot.
 * WHY:  Splits the array construction from the per-entry shape so the caller
 *       stays a single set_new call.
 * HOW:  Returns NULL on OOM of the array itself; per-entry OOM skips that slot.
 */
static json_t *
dashboard_build_cache_listeners(const ngx_brix_metrics_t *met, ngx_uint_t redact)
{
    json_t     *listeners = json_array();
    ngx_uint_t  i;

    if (!listeners) { return NULL; }
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        const ngx_brix_srv_metrics_t *srv = &met->servers[i];
        json_t                       *entry;

        if (!srv->in_use || !srv->cache_enabled) { continue; }
        entry = dashboard_build_cache_listener(srv, redact);
        if (!entry) { continue; }
        json_array_append_new(listeners, entry);
    }
    return listeners;
}


/*
 * dashboard_fill_cache — adds "enabled", "listeners", and "write_through"
 * directly to `target`.  Called with target=root for v1/cache (flat shape)
 * and with target=sub-object for snapshot (nested under "cache").
 */
void
dashboard_fill_cache(json_t *target, ngx_uint_t redact)
{
    ngx_brix_metrics_t   *met;
    ngx_uint_t            i;
    ngx_uint_t            enabled = 0;
    dashboard_wt_totals_t wt_t = { 0, 0, 0, 0, 0 };

    if (ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        dashboard_fill_cache_empty(target);
        return;
    }

    met = ngx_brix_shm_zone->data;
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        if (met->servers[i].in_use && met->servers[i].cache_enabled) { enabled = 1; }
        wt_t.dirty   += (uint64_t) met->servers[i].wt_dirty_handles;
        wt_t.pending += (uint64_t) met->servers[i].wt_flush_pending;
        wt_t.success += (uint64_t) met->servers[i].wt_flush_success_total;
        wt_t.errors  += (uint64_t) met->servers[i].wt_flush_error_total;
        wt_t.bytes   += (uint64_t) met->servers[i].wt_flush_bytes_total;
    }

    json_object_set_new(target, "enabled",       enabled ? json_true() : json_false());
    json_object_set_new(target, "listeners",     dashboard_build_cache_listeners(met, redact));
    json_object_set_new(target, "write_through", dashboard_build_write_through(&wt_t));
}


/*
 * dashboard_fill_storage — adds "exports" (per-export backend identity plus
 * live-statvfs capacity for local backends) and "io" (per-backend byte
 * totals) to `target`. The identity source is the config-time VFS backend
 * registry (the same census behind /vfs and the storage-backend info gauge),
 * so it covers stream AND http exports. redact (anonymous tier) omits the
 * export root and origin host — numbers only, matching the cache panel.
 */
/*
 * WHAT: Build one "exports" entry from a VFS backend census record.
 * WHY:  Keeps the per-export identity + capacity shape in one place so the
 *       array loop stays flat.
 * HOW:  "remote" is the inverse of a local (posix/pblock) backend; live-statvfs
 *       capacity is only statted for local backends. `redact` drops the export
 *       root and origin host (infra detail) for the anonymous tier. Returns
 *       NULL on OOM.
 */
static json_t *
dashboard_build_storage_export(const brix_vfs_backend_info_t *info,
    ngx_uint_t redact)
{
    brix_fs_usage_t fsu;
    json_t         *e = json_object();
    int             local;

    if (e == NULL) { return NULL; }

    local = ngx_strcmp(info->backend, "posix") == 0
            || ngx_strcmp(info->backend, "pblock") == 0;

    json_object_set_new(e, "backend", json_string(info->backend));
    json_object_set_new(e, "remote",  local ? json_false() : json_true());
    json_object_set_new(e, "staging",
        info->staging ? json_true() : json_false());
    if (!redact) {   /* export path + upstream host are infra detail */
        json_object_set_new(e, "root", json_string(info->root_canon));
        if (info->host != NULL && info->host[0] != '\0') {
            json_object_set_new(e, "origin_host", json_string(info->host));
            json_object_set_new(e, "origin_port",
                json_integer((json_int_t) info->port));
        }
    }
    if (local
        && brix_fs_usage_stat(info->root_canon, &fsu) == NGX_OK)
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
    return e;
}


/*
 * WHAT: Build the "exports" array from the config-time VFS backend registry.
 * WHY:  The identity census covers both stream and http exports; splitting the
 *       loop out keeps dashboard_fill_storage a pair of set_new calls.
 * HOW:  Returns NULL on OOM of the array; per-entry OOM/failed-info skips.
 */
static json_t *
dashboard_build_storage_exports(ngx_uint_t redact)
{
    json_t     *exports = json_array();
    ngx_uint_t  i, n;

    if (exports == NULL) { return NULL; }
    n = brix_vfs_backend_export_count();
    for (i = 0; i < n; i++) {
        brix_vfs_backend_info_t info;
        json_t                 *e;

        if (brix_vfs_backend_export_info(i, &info) != NGX_OK) {
            continue;
        }
        e = dashboard_build_storage_export(&info, redact);
        if (e == NULL) {
            continue;
        }
        json_array_append_new(exports, e);
    }
    return exports;
}


/*
 * WHAT: Build the "io" object — per-backend read/written byte totals.
 * WHY:  Isolates the SHM read + idle-backend filtering from the export census.
 * HOW:  Returns NULL on OOM of the object; when the metrics zone is absent the
 *       object is emitted empty (no backends). Idle backends (0/0) are omitted.
 */
static json_t *
dashboard_build_storage_io(void)
{
    json_t *io = json_object();

    if (io == NULL) { return NULL; }
    if (ngx_brix_shm_zone != NULL
        && ngx_brix_shm_zone->data != NULL
        && ngx_brix_shm_zone->data != (void *) 1)
    {
        ngx_brix_metrics_t *met = ngx_brix_shm_zone->data;
        int                 id;

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
    return io;
}


/*
 * WHAT: Populate the snapshot "storage" panel ("exports" + "io") on `target`.
 * WHY:  Cross-file seam: called from dashboard_build_v1_snapshot in
 *       api_snapshot.c — declared in dashboard_api_internal.h.
 * HOW:  Build each sub-object independently; attach only the non-NULL ones so
 *       an OOM in one panel does not drop the other.
 */
void
dashboard_fill_storage(json_t *target, ngx_uint_t redact)
{
    json_t *exports = dashboard_build_storage_exports(redact);
    json_t *io      = dashboard_build_storage_io();

    if (exports != NULL) {
        json_object_set_new(target, "exports", exports);
    }
    if (io != NULL) {
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
