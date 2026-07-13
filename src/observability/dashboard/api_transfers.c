/*
 * api_transfers.c - extracted concern
 * Phase-38 split of api.c; behavior-identical.
 */
#include "dashboard_api_internal.h"


/*
 * WHAT:  Point-in-time snapshot of one SHM transfer slot.
 * WHY:   Slots live in cross-process SHM and are mutated by worker processes
 *        without locking. Copying every field into this file-local struct BEFORE
 *        any jansson allocation prevents a field changing mid-build (torn rows)
 *        and avoids holding SHM pointers across allocator calls. Passing the
 *        struct by pointer keeps every JSON-stage helper below to <=5 params
 *        without reintroducing globals.
 * NOTE:  char[] copies mirror the SHM field sizes and are always NUL-terminated
 *        since SHM strings may be unterminated if truncated. The derived scalars
 *        (idle_ms, avg_bps, instant_bps) are computed once here.
 */
typedef struct {
    int64_t  last_ms;
    int64_t  bytes;
    int64_t  start_ms;
    int64_t  idle_ms;
    uint64_t avg_bps;
    uint64_t instant_bps;
    char     client_ip[BRIX_DASHBOARD_IP_LEN];
    char     identity[BRIX_DASHBOARD_IDENTITY_LEN];
    char     vo[BRIX_DASHBOARD_VO_LEN];
    char     path[BRIX_DASHBOARD_PATH_LEN];
    char     op[BRIX_DASHBOARD_OP_LEN];
    char     last_error[BRIX_DASHBOARD_REASON_LEN];
    char     remote_host[BRIX_DASHBOARD_HOST_LEN];
    char     remote_path[BRIX_DASHBOARD_PATH_LEN];
} dashboard_xfer_snapshot_t;


/*
 * WHAT: Decay the published EWMA instant rate for read-only display.
 * WHY:  The owning worker only re-folds slot->instant_bps while bytes flow
 *       (transfer_table.c), so a transfer sitting in an inter-burst gap would
 *       otherwise show its last burst rate frozen. Fold in the zero-rate sample
 *       intervals elapsed since the last worker sample (same alpha = 1/4) so the
 *       shown rate eases toward zero during the gap.
 * HOW:  Purely local — never writes the SHM slot. The loop is bounded:
 *       instant_bps reaches 0 within ~log_{4/3} iterations.
 */
static uint64_t
dashboard_decay_instant_bps(const brix_transfer_slot_t *slot, int64_t now_ms)
{
    uint64_t instant_bps = (uint64_t) slot->instant_bps;
    int64_t  sample_ms    = (int64_t) slot->last_sample_ms;
    int64_t  missed       = (sample_ms > 0 && now_ms > sample_ms)
                            ? (now_ms - sample_ms) / BRIX_XFER_SAMPLE_MS : 0;

    while (missed-- > 0 && instant_bps > 0) {
        instant_bps = (instant_bps * 3) / 4;   /* EWMA fold with raw = 0 */
    }
    return instant_bps;
}


/*
 * WHAT: NUL-terminate one fixed-size char[] copied from an SHM string.
 * WHY:  SHM strings may be unterminated if truncated; every string field must be
 *       forced-terminated after the ngx_memcpy before jansson touches it.
 */
static void
dashboard_snap_str(char *dst, const char *src, size_t size)
{
    ngx_memcpy(dst, src, size);
    dst[size - 1] = '\0';
}


/*
 * WHAT: Copy an SHM transfer slot into a stable local snapshot.
 * WHY:  See dashboard_xfer_snapshot_t — this is the barriered, one-shot capture
 *       that decouples the JSON build from concurrent worker mutation.
 * HOW:  Issue a memory barrier, copy scalars, derive idle_ms/avg_bps/instant_bps,
 *       then copy and terminate each string field.
 */
static void
dashboard_snapshot_slot(dashboard_xfer_snapshot_t *snap,
    const brix_transfer_slot_t *slot, int64_t now_ms)
{
    /* Barrier: ensure subsequent reads see a coherent view of the SHM slot
     * rather than reordered/cached fields from a concurrent writer. */
    ngx_memory_barrier();

    snap->last_ms     = (int64_t) slot->last_ms;
    snap->bytes       = (int64_t) slot->bytes;
    snap->start_ms    = slot->start_ms;
    snap->idle_ms     = (snap->last_ms > 0 && now_ms >= snap->last_ms)
                        ? now_ms - snap->last_ms : 0;
    snap->avg_bps     = dashboard_avg_bps(snap->bytes, snap->start_ms, now_ms);
    snap->instant_bps = dashboard_decay_instant_bps(slot, now_ms);

    dashboard_snap_str(snap->client_ip,   slot->client_ip,            sizeof(snap->client_ip));
    dashboard_snap_str(snap->identity,    slot->identity,             sizeof(snap->identity));
    dashboard_snap_str(snap->vo,          slot->vo,                   sizeof(snap->vo));
    dashboard_snap_str(snap->path,        slot->path,                 sizeof(snap->path));
    dashboard_snap_str(snap->op,          slot->op,                   sizeof(snap->op));
    dashboard_snap_str(snap->last_error,  slot->last_error,           sizeof(snap->last_error));
    dashboard_snap_str(snap->remote_host, slot->tpc_remote_host,      sizeof(snap->remote_host));
    dashboard_snap_str(snap->remote_path, slot->tpc_remote_path_hint, sizeof(snap->remote_path));
}


/*
 * WHAT: Emit the compat base fields shared by every transfer row.
 * WHY:  These are the fields the legacy /xrootd/transfers shape stops at; both
 *       compat and v1 rows begin identically.
 * HOW:  redact==1 (anonymous viewer) scrubs PII — IP, identity/DN, path. Keys
 *       stay so the table layout is stable; the most-identifying ones go empty.
 */
static void
dashboard_emit_base_fields(json_t *obj, const brix_transfer_slot_t *slot,
    const dashboard_xfer_snapshot_t *snap, ngx_uint_t redact)
{
    json_object_set_new(obj, "id",        json_integer((json_int_t) slot->serial));
    json_object_set_new(obj, "client",    json_string(redact ? "[redacted]" : snap->client_ip));
    json_object_set_new(obj, "identity",  json_string(redact ? "" : snap->identity));
    json_object_set_new(obj, "path",      json_string(redact ? "[redacted]" : snap->path));
    json_object_set_new(obj, "direction", json_string(dashboard_direction_name(slot->direction)));
    json_object_set_new(obj, "protocol",  json_string(dashboard_proto_name(slot->proto)));
    json_object_set_new(obj, "bytes",     json_integer((json_int_t) snap->bytes));
    json_object_set_new(obj, "start_ms",  json_integer((json_int_t) snap->start_ms));
    json_object_set_new(obj, "last_ms",   json_integer((json_int_t) snap->last_ms));
}


/*
 * WHAT: Emit the richer v1 scalar fields (identity, op, state, rates, timings).
 * WHY:  v1_fields gates the v1 schema on top of the compat base.
 * HOW:  worker_pid is a host fingerprint and last_error routinely embeds
 *       paths/hosts/DNs — both are omitted/blanked for anonymous viewers.
 */
static void
dashboard_emit_v1_fields(json_t *obj,
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    const brix_transfer_slot_t *slot,
    const dashboard_xfer_snapshot_t *snap, ngx_uint_t redact)
{
    if (!redact) {   /* worker_pid is a host fingerprint — omit for anonymous */
        json_object_set_new(obj, "worker_pid", json_integer((json_int_t) slot->worker_pid));
    }
    json_object_set_new(obj, "vo",            json_string(redact ? "" : snap->vo));
    json_object_set_new(obj, "op",            json_string(snap->op));
    json_object_set_new(obj, "state",         json_string(dashboard_state_name(conf, slot->state, snap->idle_ms, snap->avg_bps > 0)));
    json_object_set_new(obj, "expected_bytes",json_integer((json_int_t) slot->expected_bytes));
    json_object_set_new(obj, "instant_bps",   json_integer((json_int_t) snap->instant_bps));
    json_object_set_new(obj, "avg_bps",       json_integer((json_int_t) snap->avg_bps));
    json_object_set_new(obj, "idle_ms",       json_integer((json_int_t) snap->idle_ms));
    json_object_set_new(obj, "state_since_ms",json_integer((json_int_t) slot->state_since_ms));
    json_object_set_new(obj, "last_error",    json_string(redact ? "" : snap->last_error));
}


/*
 * WHAT: Attach the nested "tpc" object when this row involves a remote peer.
 * WHY:  Emit it only for a TPC transfer, or when a remote host/path hint was
 *       recorded (e.g. a proxied operation) — avoids cluttering plain local rows.
 */
static void
dashboard_emit_tpc_object(json_t *obj, const brix_transfer_slot_t *slot,
    const dashboard_xfer_snapshot_t *snap, ngx_uint_t redact)
{
    json_t *tpc;

    if (slot->direction != BRIX_XFER_DIR_TPC
        && snap->remote_host[0] == '\0' && snap->remote_path[0] == '\0')
    {
        return;
    }

    tpc = json_object();
    if (!tpc) { return; }

    json_object_set_new(tpc, "remote_host",   json_string(redact ? "[redacted]" : snap->remote_host));
    json_object_set_new(tpc, "path_hint",     json_string(redact ? "" : snap->remote_path));
    json_object_set_new(tpc, "remote_status", json_integer(slot->tpc_remote_status));
    json_object_set_new(tpc, "curl_exit",     json_integer(slot->tpc_curl_exit));
    json_object_set_new(obj, "tpc", tpc);
}


/*
 * WHAT: Emit the session hash and per-op counters for the detail endpoint.
 * WHY:  detail_fields is set only by the single-transfer detail endpoint; these
 *       fields are absent from the list views.
 */
static void
dashboard_emit_detail_fields(json_t *obj, const brix_transfer_slot_t *slot)
{
    char    hash_str[9];
    json_t *counters;

    snprintf(hash_str, sizeof(hash_str), "%08x",
             dashboard_session_hash(slot->sessid));
    json_object_set_new(obj, "session_hash", json_string(hash_str));

    counters = json_object();
    if (!counters) { return; }

    json_object_set_new(counters, "read_ops",  json_integer((json_int_t) slot->read_ops));
    json_object_set_new(counters, "write_ops", json_integer((json_int_t) slot->write_ops));
    json_object_set_new(counters, "sync_ops",  json_integer((json_int_t) slot->sync_ops));
    json_object_set_new(counters, "close_ops", json_integer((json_int_t) slot->close_ops));
    json_object_set_new(obj, "counters", counters);
}


/*
 * WHAT: Serialise one transfer slot into a JSON object.
 * WHY:  Snapshots the SHM slot once (dashboard_snapshot_slot), then emits each
 *       cohesive field group through a dedicated stage helper. This keeps the
 *       point-in-time-consistency guarantee (no torn rows, no SHM pointer held
 *       across allocation) while staying under the complexity budget.
 * NOTE: v1_fields gates the richer v1 schema; detail_fields adds per-op counters
 *       and the session hash (only the single-transfer detail endpoint sets it).
 */
json_t *
dashboard_build_transfer_object(
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    const brix_transfer_slot_t *slot, int64_t now_ms,
    ngx_uint_t v1_fields, ngx_uint_t detail_fields, ngx_uint_t redact)
{
    dashboard_xfer_snapshot_t snap;
    json_t                   *obj;

    ngx_memzero(&snap, sizeof(snap));
    dashboard_snapshot_slot(&snap, slot, now_ms);

    obj = json_object();
    if (!obj) { return NULL; }

    dashboard_emit_base_fields(obj, slot, &snap, redact);

    /* Compat (/xrootd/transfers) shape stops here; v1 adds the fields below. */
    if (!v1_fields) { return obj; }

    dashboard_emit_v1_fields(obj, conf, slot, &snap, redact);
    dashboard_emit_tpc_object(obj, slot, &snap, redact);

    if (detail_fields) {
        dashboard_emit_detail_fields(obj, slot);
    }

    return obj;
}


json_t *
dashboard_build_transfer_rows(int64_t now_ms,
    const ngx_http_brix_dashboard_loc_conf_t *conf, ngx_uint_t v1_fields,
    ngx_uint_t redact)
{
    brix_transfer_table_t *tbl;
    json_t                  *arr;
    ngx_uint_t               i;

    arr = json_array();
    if (!arr) { return NULL; }

    if (ngx_brix_dashboard_shm_zone == NULL
        || ngx_brix_dashboard_shm_zone->data == NULL
        || ngx_brix_dashboard_shm_zone->data == (void *) 1)
    {
        return arr;
    }

    tbl = ngx_brix_dashboard_shm_zone->data;
    for (i = 0; i < BRIX_DASHBOARD_MAX_TRANSFERS; i++) {
        brix_transfer_slot_t *slot = &tbl->slots[i];
        int64_t                 last_ms;
        json_t                 *obj;

        if (slot->in_use == 0) { continue; }

        /* Opportunistic GC: a slot whose last activity is older than STALE_GC_MS
         * almost certainly leaked (worker died without freeing it). Reclaim it
         * here on the read path — there is no separate sweeper — and record an
         * event so the cleanup is visible, then skip emitting the dead row. */
        last_ms = (int64_t) slot->last_ms;
        if (last_ms > 0 && now_ms - last_ms > STALE_GC_MS) {
            brix_dashboard_event_add(BRIX_DASH_EVENT_DASHBOARD,
                                       slot->proto, 0,
                                       "stale active transfer cleaned up",
                                       slot->path);
            brix_transfer_slot_free(tbl, (int) i);
            continue;
        }

        obj = dashboard_build_transfer_object(conf, slot, now_ms, v1_fields, 0, redact);
        if (obj) { json_array_append_new(arr, obj); }
    }
    return arr;
}


json_t *
dashboard_build_tpc_registry(ngx_pool_t *pool, ngx_uint_t redact)
{
    brix_tpc_transfer_snapshot_t *rows;
    ngx_uint_t                      n, i;
    json_t                         *arr;

    arr = json_array();
    if (!arr) { return NULL; }

    rows = ngx_pcalloc(pool, sizeof(*rows) * TPC_REGISTRY_JSON_LIMIT);
    if (rows == NULL) { return arr; }

    n = brix_tpc_registry_snapshot(rows, TPC_REGISTRY_JSON_LIMIT);
    for (i = 0; i < n; i++) {
        json_t *entry = json_object();
        if (!entry) { continue; }
        json_object_set_new(entry, "id",          json_integer((json_int_t) rows[i].id));
        json_object_set_new(entry, "protocol",    json_string(dashboard_tpc_protocol_name(rows[i].protocol)));
        json_object_set_new(entry, "direction",   json_string(dashboard_tpc_direction_name(rows[i].direction)));
        json_object_set_new(entry, "state",       json_string(dashboard_tpc_state_name(rows[i].state)));
        json_object_set_new(entry, "source",      json_string(redact ? "[redacted]" : rows[i].src_url));
        json_object_set_new(entry, "destination", json_string(redact ? "" : rows[i].dst_path));
        json_object_set_new(entry, "bytes_done",  json_integer((json_int_t) rows[i].bytes_done));
        json_object_set_new(entry, "bytes_total", json_integer((json_int_t) rows[i].bytes_total));
        json_object_set_new(entry, "started_at",  json_integer((json_int_t) rows[i].started_at));
        json_object_set_new(entry, "updated_at",  json_integer((json_int_t) rows[i].updated_at));
        json_array_append_new(arr, entry);
    }
    return arr;
}


json_t *
dashboard_build_compat_transfers(int64_t now_ms,
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    const brix_dashboard_totals_t *totals, ngx_uint_t redact)
{
    json_t *root = json_object();
    if (!root) { return NULL; }
    json_object_set_new(root, "server_ms",        json_integer((json_int_t) now_ms));
    json_object_set_new(root, "anonymous",         redact ? json_true() : json_false());
    json_object_set_new(root, "active_transfers",  dashboard_build_transfer_rows(now_ms, conf, 0, redact));
    json_object_set_new(root, "totals",            dashboard_build_totals(totals));
    return root;
}


json_t *
dashboard_build_v1_transfers(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_brix_dashboard_loc_conf_t *conf,
    const brix_dashboard_totals_t *totals, ngx_uint_t redact)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous",        redact ? json_true() : json_false());
    json_object_set_new(root, "active_transfers", dashboard_build_transfer_rows(now_ms, conf, 1, redact));
    json_object_set_new(root, "tpc_transfers",    dashboard_build_tpc_registry(r->pool, redact));
    json_object_set_new(root, "totals",           dashboard_build_totals(totals));
    return root;
}


/*
 * Parse the numeric transfer id from "/brix/api/v1/transfers/<id>".
 * Strict: the tail must be present and consist solely of decimal digits — any
 * non-digit (path traversal, trailing slash, query) yields NGX_DECLINED so the
 * caller returns 400 rather than risking a misparse.
 */
ngx_int_t
dashboard_parse_detail_id(ngx_http_request_t *r, uint32_t *id)
{
    const char *prefix = "/brix/api/v1/transfers/";
    size_t      prefix_len = sizeof("/brix/api/v1/transfers/") - 1;
    uint32_t    value = 0;
    size_t      i;

    if (r->uri.len <= prefix_len
        || ngx_memcmp(r->uri.data, prefix, prefix_len) != 0)
    {
        return NGX_DECLINED;
    }

    /* Accumulate base-10; reject on the first non-digit byte. */
    for (i = prefix_len; i < r->uri.len; i++) {
        u_char c = r->uri.data[i];
        if (c < '0' || c > '9') { return NGX_DECLINED; }
        value = value * 10u + (uint32_t) (c - '0');
    }

    *id = value;
    return NGX_OK;
}


json_t *
dashboard_build_v1_transfer_detail(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_brix_dashboard_loc_conf_t *conf,
    ngx_int_t *status)
{
    brix_transfer_table_t *tbl;
    uint32_t                 id;
    ngx_uint_t               i;
    json_t                  *root;

    *status = NGX_HTTP_NOT_FOUND;
    root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }

    if (dashboard_parse_detail_id(r, &id) != NGX_OK) {
        *status = NGX_HTTP_BAD_REQUEST;
        json_object_set_new(root, "error", json_string("bad_transfer_id"));
        return root;
    }

    if (ngx_brix_dashboard_shm_zone == NULL
        || ngx_brix_dashboard_shm_zone->data == NULL
        || ngx_brix_dashboard_shm_zone->data == (void *) 1)
    {
        json_object_set_new(root, "error", json_string("not_found"));
        return root;
    }

    tbl = ngx_brix_dashboard_shm_zone->data;
    for (i = 0; i < BRIX_DASHBOARD_MAX_TRANSFERS; i++) {
        brix_transfer_slot_t *slot = &tbl->slots[i];
        if (slot->in_use && slot->serial == id) {
            *status = NGX_HTTP_OK;
            json_object_set_new(root, "transfer",
                dashboard_build_transfer_object(conf, slot, now_ms, 1, 1, 0));
            return root;
        }
    }

    json_object_set_new(root, "error", json_string("not_found"));
    return root;
}
