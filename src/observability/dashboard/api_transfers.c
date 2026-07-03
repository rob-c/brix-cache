/*
 * api_transfers.c - extracted concern
 * Phase-38 split of api.c; behavior-identical.
 */
#include "dashboard_api_internal.h"


/*
 * WHAT: Serialise one transfer slot into a JSON object.
 * WHY:  The slot lives in cross-process SHM and is mutated by worker processes
 *       without locking. We take a consistent point-in-time snapshot: issue a
 *       memory barrier, then copy every field to local stack vars BEFORE any
 *       jansson allocation. This prevents a field changing mid-build (which could
 *       otherwise produce a torn/inconsistent row) and avoids holding SHM
 *       pointers across allocator calls. All char[] copies are explicitly
 *       NUL-terminated since SHM strings may be unterminated if truncated.
 * NOTE: v1_fields gates the richer v1 schema; detail_fields adds per-op counters
 *       and the session hash (only the single-transfer detail endpoint sets it).
 */
json_t *
dashboard_build_transfer_object(
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    const brix_transfer_slot_t *slot, int64_t now_ms,
    ngx_uint_t v1_fields, ngx_uint_t detail_fields, ngx_uint_t redact)
{
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
    json_t  *obj;

    /* Barrier: ensure subsequent reads see a coherent view of the SHM slot
     * rather than reordered/cached fields from a concurrent writer. */
    ngx_memory_barrier();

    last_ms     = (int64_t) slot->last_ms;
    bytes       = (int64_t) slot->bytes;
    start_ms    = slot->start_ms;
    idle_ms     = (last_ms > 0 && now_ms >= last_ms) ? now_ms - last_ms : 0;
    avg_bps     = dashboard_avg_bps(bytes, start_ms, now_ms);

    /*
     * Published EWMA rate, decayed read-only for display.  The owning worker
     * only re-folds slot->instant_bps while bytes flow (transfer_table.c), so a
     * transfer sitting in an inter-burst gap would otherwise show its last burst
     * rate frozen.  Fold in the zero-rate sample intervals elapsed since the
     * last worker sample (same alpha = 1/4) so the shown rate eases toward zero
     * during the gap.  Purely local — never writes the SHM slot.  The loop is
     * bounded: instant_bps reaches 0 within ~log_{4/3} iterations.
     */
    instant_bps = (uint64_t) slot->instant_bps;
    {
        int64_t sample_ms = (int64_t) slot->last_sample_ms;
        int64_t missed    = (sample_ms > 0 && now_ms > sample_ms)
                            ? (now_ms - sample_ms) / BRIX_XFER_SAMPLE_MS : 0;
        while (missed-- > 0 && instant_bps > 0) {
            instant_bps = (instant_bps * 3) / 4;   /* EWMA fold with raw = 0 */
        }
    }

    ngx_memcpy(client_ip,   slot->client_ip,            sizeof(client_ip));
    ngx_memcpy(identity,    slot->identity,             sizeof(identity));
    ngx_memcpy(vo,          slot->vo,                   sizeof(vo));
    ngx_memcpy(path,        slot->path,                 sizeof(path));
    ngx_memcpy(op,          slot->op,                   sizeof(op));
    ngx_memcpy(last_error,  slot->last_error,           sizeof(last_error));
    ngx_memcpy(remote_host, slot->tpc_remote_host,      sizeof(remote_host));
    ngx_memcpy(remote_path, slot->tpc_remote_path_hint, sizeof(remote_path));
    client_ip[sizeof(client_ip)     - 1] = '\0';
    identity[sizeof(identity)       - 1] = '\0';
    vo[sizeof(vo)                   - 1] = '\0';
    path[sizeof(path)               - 1] = '\0';
    op[sizeof(op)                   - 1] = '\0';
    last_error[sizeof(last_error)   - 1] = '\0';
    remote_host[sizeof(remote_host) - 1] = '\0';
    remote_path[sizeof(remote_path) - 1] = '\0';

    obj = json_object();
    if (!obj) { return NULL; }

    json_object_set_new(obj, "id",        json_integer((json_int_t) slot->serial));
    /* redact==1 (anonymous viewer): scrub PII — IP, identity/DN, and path. Keys
     * stay so the table layout is stable; the most-identifying ones go empty. */
    json_object_set_new(obj, "client",    json_string(redact ? "[redacted]" : client_ip));
    json_object_set_new(obj, "identity",  json_string(redact ? "" : identity));
    json_object_set_new(obj, "path",      json_string(redact ? "[redacted]" : path));
    json_object_set_new(obj, "direction", json_string(dashboard_direction_name(slot->direction)));
    json_object_set_new(obj, "protocol",  json_string(dashboard_proto_name(slot->proto)));
    json_object_set_new(obj, "bytes",     json_integer((json_int_t) bytes));
    json_object_set_new(obj, "start_ms",  json_integer((json_int_t) start_ms));
    json_object_set_new(obj, "last_ms",   json_integer((json_int_t) last_ms));

    /* Compat (/xrootd/transfers) shape stops here; v1 adds the fields below. */
    if (!v1_fields) { return obj; }

    if (!redact) {   /* worker_pid is a host fingerprint — omit for anonymous */
        json_object_set_new(obj, "worker_pid", json_integer((json_int_t) slot->worker_pid));
    }
    json_object_set_new(obj, "vo",            json_string(redact ? "" : vo));
    json_object_set_new(obj, "op",            json_string(op));
    json_object_set_new(obj, "state",         json_string(dashboard_state_name(conf, slot->state, idle_ms, avg_bps > 0)));
    json_object_set_new(obj, "expected_bytes",json_integer((json_int_t) slot->expected_bytes));
    json_object_set_new(obj, "instant_bps",   json_integer((json_int_t) instant_bps));
    json_object_set_new(obj, "avg_bps",       json_integer((json_int_t) avg_bps));
    json_object_set_new(obj, "idle_ms",       json_integer((json_int_t) idle_ms));
    json_object_set_new(obj, "state_since_ms",json_integer((json_int_t) slot->state_since_ms));
    /* last_error routinely embeds paths/hosts/DNs — omit it for anonymous. */
    json_object_set_new(obj, "last_error",    json_string(redact ? "" : last_error));

    /* Emit the nested "tpc" object only when this row actually involves a remote
     * peer: either it is a TPC transfer, or a remote host/path hint was recorded
     * (e.g. a proxied operation). Avoids cluttering plain local transfers. */
    if (slot->direction == BRIX_XFER_DIR_TPC
        || remote_host[0] != '\0' || remote_path[0] != '\0')
    {
        json_t *tpc = json_object();
        if (tpc) {
            json_object_set_new(tpc, "remote_host",   json_string(redact ? "[redacted]" : remote_host));
            json_object_set_new(tpc, "path_hint",     json_string(redact ? "" : remote_path));
            json_object_set_new(tpc, "remote_status", json_integer(slot->tpc_remote_status));
            json_object_set_new(tpc, "curl_exit",     json_integer(slot->tpc_curl_exit));
            json_object_set_new(obj, "tpc", tpc);
        }
    }

    if (detail_fields) {
        char    hash_str[9];
        json_t *counters = json_object();
        snprintf(hash_str, sizeof(hash_str), "%08x",
                 dashboard_session_hash(slot->sessid));
        json_object_set_new(obj, "session_hash", json_string(hash_str));
        if (counters) {
            json_object_set_new(counters, "read_ops",  json_integer((json_int_t) slot->read_ops));
            json_object_set_new(counters, "write_ops", json_integer((json_int_t) slot->write_ops));
            json_object_set_new(counters, "sync_ops",  json_integer((json_int_t) slot->sync_ops));
            json_object_set_new(counters, "close_ops", json_integer((json_int_t) slot->close_ops));
            json_object_set_new(obj, "counters", counters);
        }
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
