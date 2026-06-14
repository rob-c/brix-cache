#include "dashboard_http.h"

#include "../compat/fs_usage.h"
#include "../manager/registry.h"
#include "../tpc/common/registry.h"
#include "../ratelimit/ratelimit.h"

#include <stdio.h>
#include <string.h>
#include <jansson.h>

/*
 * dashboard/api.c - dashboard JSON endpoints.
 *
 * /xrootd/transfers keeps its original shape.  /xrootd/api/v1/...
 * exposes the richer, schema-tagged dashboard API used by the enhanced page
 * and external tooling.
 *
 * JSON serialisation uses jansson: builders return json_t * rather than
 * writing into a fixed 1 MB pool buffer.  The final response is sized to
 * the actual payload via json_dumpb().
 */

#define STALE_GC_MS             600000
#define TPC_REGISTRY_JSON_LIMIT 64

typedef struct {
    uint64_t  conn_active;
    uint64_t  conn_total;
    uint64_t  bytes_rx;
    uint64_t  bytes_tx;
    uint64_t  wdav_rx;
    uint64_t  wdav_tx;
    uint64_t  s3_rx;
    uint64_t  s3_tx;
    uint64_t  stream_errors;
    uint64_t  webdav_errors;
    uint64_t  s3_errors;
} xrootd_dashboard_totals_t;

typedef struct {
    ngx_uint_t active;
    uint64_t   ingress_bps;
    uint64_t   egress_bps;
} xrootd_dashboard_proto_summary_t;

typedef struct {
    xrootd_dashboard_proto_summary_t root;
    xrootd_dashboard_proto_summary_t webdav;
    xrootd_dashboard_proto_summary_t s3;
    xrootd_dashboard_proto_summary_t tpc;
} xrootd_dashboard_protocols_t;

static const char *
dashboard_direction_name(uint8_t direction)
{
    switch (direction) {
    case XROOTD_XFER_DIR_WRITE: return "write";
    case XROOTD_XFER_DIR_TPC:   return "tpc";
    default:                    return "read";
    }
}

static const char *
dashboard_proto_name(uint8_t proto)
{
    switch (proto) {
    case XROOTD_XFER_PROTO_WEBDAV: return "webdav";
    case XROOTD_XFER_PROTO_S3:     return "s3";
    default:                       return "root";
    }
}

static const char *
dashboard_state_name(const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    uint8_t state, int64_t idle_ms)
{
    if (state == XROOTD_XFER_STATE_ERROR)   { return "error"; }
    if (state == XROOTD_XFER_STATE_CLOSING) { return "closing"; }
    if (idle_ms >= (int64_t) conf->stalled_threshold_ms) { return "stalled"; }
    if (idle_ms >= (int64_t) conf->idle_threshold_ms)    { return "idle"; }
    return "active";
}

static const char *
dashboard_tpc_protocol_name(ngx_uint_t protocol)
{
    switch (protocol) {
    case XROOTD_TPC_PROTO_STREAM: return "stream";
    case XROOTD_TPC_PROTO_WEBDAV: return "webdav";
    default:                      return "unknown";
    }
}

static const char *
dashboard_tpc_direction_name(ngx_uint_t direction)
{
    switch (direction) {
    case XROOTD_TPC_DIR_PUSH: return "push";
    case XROOTD_TPC_DIR_PULL: return "pull";
    default:                  return "unknown";
    }
}

static const char *
dashboard_tpc_state_name(ngx_uint_t state)
{
    switch (state) {
    case XROOTD_TPC_STATE_PENDING: return "pending";
    case XROOTD_TPC_STATE_ACTIVE:  return "active";
    case XROOTD_TPC_STATE_DONE:    return "done";
    case XROOTD_TPC_STATE_ERROR:   return "error";
    default:                       return "unknown";
    }
}

static const char *
dashboard_event_class_name(uint8_t class_id)
{
    switch (class_id) {
    case XROOTD_DASH_EVENT_AUTH:      return "auth";
    case XROOTD_DASH_EVENT_NAMESPACE: return "namespace";
    case XROOTD_DASH_EVENT_IO:        return "io";
    case XROOTD_DASH_EVENT_TPC:       return "tpc";
    case XROOTD_DASH_EVENT_DASHBOARD: return "dashboard";
    default:                          return "unknown";
    }
}

/*
 * WHAT: Fold a 16-byte session id into a 32-bit value (FNV-1a hash).
 * WHY:  The dashboard exposes a short "session_hash" so an operator can
 *       correlate rows without leaking the raw session id. NOT for security —
 *       it is non-cryptographic and only needs to be stable per session.
 * HOW:  Standard FNV-1a: 2166136261 offset basis, 16777619 prime.
 */
static uint32_t
dashboard_session_hash(const u_char sessid[16])
{
    uint32_t   h = 2166136261u;
    ngx_uint_t i;

    for (i = 0; i < 16; i++) {
        h ^= sessid[i];
        h *= 16777619u;
    }
    return h;
}

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
static void
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

/* Average bytes/sec over a transfer's lifetime. Guards against a zero/negative
 * elapsed window (clock not advanced, or start in the future) to avoid divide-
 * by-zero; the *1000 converts the ms denominator to a per-second rate. */
static uint64_t
dashboard_avg_bps(int64_t bytes, int64_t start_ms, int64_t now_ms)
{
    int64_t elapsed_ms;

    elapsed_ms = (start_ms > 0 && now_ms > start_ms) ? now_ms - start_ms : 0;
    return elapsed_ms > 0 ? (uint64_t) ((bytes * 1000) / elapsed_ms) : 0;
}

/*
 * WHAT: Tally live transfers per protocol bucket (root/webdav/s3/tpc) from the
 *       dashboard transfer table, accumulating active counts and aggregate
 *       ingress/egress bandwidth.
 * HOW:  Each in-use slot is classified — TPC direction wins over protocol so a
 *       TPC transfer lands in the tpc bucket regardless of carrier protocol.
 *       Write transfers count toward ingress, all others toward egress.
 */
static void
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

/* -------------------------------------------------------------------------
 * Leaf builders — each returns a json_t * owned by the caller.
 * NULL return means OOM; the caller passes it to json_object_set_new which
 * handles NULL gracefully (returns -1, key absent from parent).
 * ---------------------------------------------------------------------- */

static json_t *
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

static json_t *
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
    json_object_set_new(obj, "stream_errors_total", json_integer((json_int_t) totals->stream_errors));
    json_object_set_new(obj, "webdav_errors_total", json_integer((json_int_t) totals->webdav_errors));
    json_object_set_new(obj, "s3_errors_total",     json_integer((json_int_t) totals->s3_errors));
    return obj;
}

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
static json_t *
dashboard_build_transfer_object(
    const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const xrootd_transfer_slot_t *slot, int64_t now_ms,
    ngx_uint_t v1_fields, ngx_uint_t detail_fields)
{
    int64_t  last_ms;
    int64_t  bytes;
    int64_t  start_ms;
    int64_t  idle_ms;
    uint64_t avg_bps;
    uint64_t instant_bps;
    char     client_ip[XROOTD_DASHBOARD_IP_LEN];
    char     identity[XROOTD_DASHBOARD_IDENTITY_LEN];
    char     vo[XROOTD_DASHBOARD_VO_LEN];
    char     path[XROOTD_DASHBOARD_PATH_LEN];
    char     op[XROOTD_DASHBOARD_OP_LEN];
    char     last_error[XROOTD_DASHBOARD_REASON_LEN];
    char     remote_host[XROOTD_DASHBOARD_HOST_LEN];
    char     remote_path[XROOTD_DASHBOARD_PATH_LEN];
    json_t  *obj;

    /* Barrier: ensure subsequent reads see a coherent view of the SHM slot
     * rather than reordered/cached fields from a concurrent writer. */
    ngx_memory_barrier();

    last_ms     = (int64_t) slot->last_ms;
    bytes       = (int64_t) slot->bytes;
    start_ms    = slot->start_ms;
    idle_ms     = (last_ms > 0 && now_ms >= last_ms) ? now_ms - last_ms : 0;
    avg_bps     = dashboard_avg_bps(bytes, start_ms, now_ms);
    instant_bps = (uint64_t) slot->instant_bps;

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
    json_object_set_new(obj, "client",    json_string(client_ip));
    json_object_set_new(obj, "identity",  json_string(identity));
    json_object_set_new(obj, "path",      json_string(path));
    json_object_set_new(obj, "direction", json_string(dashboard_direction_name(slot->direction)));
    json_object_set_new(obj, "protocol",  json_string(dashboard_proto_name(slot->proto)));
    json_object_set_new(obj, "bytes",     json_integer((json_int_t) bytes));
    json_object_set_new(obj, "start_ms",  json_integer((json_int_t) start_ms));
    json_object_set_new(obj, "last_ms",   json_integer((json_int_t) last_ms));

    /* Compat (/xrootd/transfers) shape stops here; v1 adds the fields below. */
    if (!v1_fields) { return obj; }

    json_object_set_new(obj, "worker_pid",    json_integer((json_int_t) slot->worker_pid));
    json_object_set_new(obj, "vo",            json_string(vo));
    json_object_set_new(obj, "op",            json_string(op));
    json_object_set_new(obj, "state",         json_string(dashboard_state_name(conf, slot->state, idle_ms)));
    json_object_set_new(obj, "expected_bytes",json_integer((json_int_t) slot->expected_bytes));
    json_object_set_new(obj, "instant_bps",   json_integer((json_int_t) instant_bps));
    json_object_set_new(obj, "avg_bps",       json_integer((json_int_t) avg_bps));
    json_object_set_new(obj, "idle_ms",       json_integer((json_int_t) idle_ms));
    json_object_set_new(obj, "state_since_ms",json_integer((json_int_t) slot->state_since_ms));
    json_object_set_new(obj, "last_error",    json_string(last_error));

    /* Emit the nested "tpc" object only when this row actually involves a remote
     * peer: either it is a TPC transfer, or a remote host/path hint was recorded
     * (e.g. a proxied operation). Avoids cluttering plain local transfers. */
    if (slot->direction == XROOTD_XFER_DIR_TPC
        || remote_host[0] != '\0' || remote_path[0] != '\0')
    {
        json_t *tpc = json_object();
        if (tpc) {
            json_object_set_new(tpc, "remote_host",   json_string(remote_host));
            json_object_set_new(tpc, "path_hint",     json_string(remote_path));
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

static json_t *
dashboard_build_transfer_rows(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t v1_fields)
{
    xrootd_transfer_table_t *tbl;
    json_t                  *arr;
    ngx_uint_t               i;

    arr = json_array();
    if (!arr) { return NULL; }

    if (ngx_xrootd_dashboard_shm_zone == NULL
        || ngx_xrootd_dashboard_shm_zone->data == NULL
        || ngx_xrootd_dashboard_shm_zone->data == (void *) 1)
    {
        return arr;
    }

    tbl = ngx_xrootd_dashboard_shm_zone->data;
    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
        xrootd_transfer_slot_t *slot = &tbl->slots[i];
        int64_t                 last_ms;
        json_t                 *obj;

        if (slot->in_use == 0) { continue; }

        /* Opportunistic GC: a slot whose last activity is older than STALE_GC_MS
         * almost certainly leaked (worker died without freeing it). Reclaim it
         * here on the read path — there is no separate sweeper — and record an
         * event so the cleanup is visible, then skip emitting the dead row. */
        last_ms = (int64_t) slot->last_ms;
        if (last_ms > 0 && now_ms - last_ms > STALE_GC_MS) {
            xrootd_dashboard_event_add(XROOTD_DASH_EVENT_DASHBOARD,
                                       slot->proto, 0,
                                       "stale active transfer cleaned up",
                                       slot->path);
            xrootd_transfer_slot_free(tbl, (int) i);
            continue;
        }

        obj = dashboard_build_transfer_object(conf, slot, now_ms, v1_fields, 0);
        if (obj) { json_array_append_new(arr, obj); }
    }
    return arr;
}

static json_t *
dashboard_build_tpc_registry(ngx_pool_t *pool)
{
    xrootd_tpc_transfer_snapshot_t *rows;
    ngx_uint_t                      n, i;
    json_t                         *arr;

    arr = json_array();
    if (!arr) { return NULL; }

    rows = ngx_pcalloc(pool, sizeof(*rows) * TPC_REGISTRY_JSON_LIMIT);
    if (rows == NULL) { return arr; }

    n = xrootd_tpc_registry_snapshot(rows, TPC_REGISTRY_JSON_LIMIT);
    for (i = 0; i < n; i++) {
        json_t *entry = json_object();
        if (!entry) { continue; }
        json_object_set_new(entry, "id",          json_integer((json_int_t) rows[i].id));
        json_object_set_new(entry, "protocol",    json_string(dashboard_tpc_protocol_name(rows[i].protocol)));
        json_object_set_new(entry, "direction",   json_string(dashboard_tpc_direction_name(rows[i].direction)));
        json_object_set_new(entry, "state",       json_string(dashboard_tpc_state_name(rows[i].state)));
        json_object_set_new(entry, "source",      json_string(rows[i].src_url));
        json_object_set_new(entry, "destination", json_string(rows[i].dst_path));
        json_object_set_new(entry, "bytes_done",  json_integer((json_int_t) rows[i].bytes_done));
        json_object_set_new(entry, "bytes_total", json_integer((json_int_t) rows[i].bytes_total));
        json_object_set_new(entry, "started_at",  json_integer((json_int_t) rows[i].started_at));
        json_object_set_new(entry, "updated_at",  json_integer((json_int_t) rows[i].updated_at));
        json_array_append_new(arr, entry);
    }
    return arr;
}

static json_t *
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

static json_t *
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

static json_t *
dashboard_build_events(ngx_pool_t *pool)
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
        json_object_set_new(ev, "message",   json_string(events[i].message));
        json_object_set_new(ev, "path_hint", json_string(events[i].path_hint));
        json_array_append_new(arr, ev);
    }
    return arr;
}

/*
 * dashboard_fill_history — adds "bucket_seconds" and "buckets" directly to
 * `target`.  Called with target=root for the v1/history endpoint (flat shape)
 * and with target=sub-object for the snapshot endpoint (nested under "history").
 */
static void
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
static void
dashboard_fill_cache(json_t *target)
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
            json_object_set_new(entry, "port", json_integer((json_int_t) srv->port));
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
static void
dashboard_fill_cluster(json_t *target, ngx_pool_t *pool, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
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
        json_object_set_new(srv, "host",              json_string(entries[i].host));
        json_object_set_new(srv, "port",              json_integer((json_int_t) entries[i].port));
        json_object_set_new(srv, "paths",             json_string(entries[i].paths));
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

/* -------------------------------------------------------------------------
 * Top-level endpoint builders
 * ---------------------------------------------------------------------- */

static json_t *
dashboard_new_v1_root(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = json_object();
    if (!root) { return NULL; }
    json_object_set_new(root, "schema",    json_string("xrootd-dashboard.v1"));
    json_object_set_new(root, "server_ms", json_integer((json_int_t) now_ms));
    json_object_set_new(root, "limits",    dashboard_build_limits(conf));
    return root;
}

static json_t *
dashboard_build_compat_transfers(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const xrootd_dashboard_totals_t *totals)
{
    json_t *root = json_object();
    if (!root) { return NULL; }
    json_object_set_new(root, "server_ms",        json_integer((json_int_t) now_ms));
    json_object_set_new(root, "active_transfers",  dashboard_build_transfer_rows(now_ms, conf, 0));
    json_object_set_new(root, "totals",            dashboard_build_totals(totals));
    return root;
}

static json_t *
dashboard_build_v1_transfers(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const xrootd_dashboard_totals_t *totals)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "active_transfers", dashboard_build_transfer_rows(now_ms, conf, 1));
    json_object_set_new(root, "tpc_transfers",    dashboard_build_tpc_registry(r->pool));
    json_object_set_new(root, "totals",           dashboard_build_totals(totals));
    return root;
}

/*
 * Parse the numeric transfer id from "/xrootd/api/v1/transfers/<id>".
 * Strict: the tail must be present and consist solely of decimal digits — any
 * non-digit (path traversal, trailing slash, query) yields NGX_DECLINED so the
 * caller returns 400 rather than risking a misparse.
 */
static ngx_int_t
dashboard_parse_detail_id(ngx_http_request_t *r, uint32_t *id)
{
    const char *prefix = "/xrootd/api/v1/transfers/";
    size_t      prefix_len = sizeof("/xrootd/api/v1/transfers/") - 1;
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

static json_t *
dashboard_build_v1_transfer_detail(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    ngx_int_t *status)
{
    xrootd_transfer_table_t *tbl;
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

    if (ngx_xrootd_dashboard_shm_zone == NULL
        || ngx_xrootd_dashboard_shm_zone->data == NULL
        || ngx_xrootd_dashboard_shm_zone->data == (void *) 1)
    {
        json_object_set_new(root, "error", json_string("not_found"));
        return root;
    }

    tbl = ngx_xrootd_dashboard_shm_zone->data;
    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
        xrootd_transfer_slot_t *slot = &tbl->slots[i];
        if (slot->in_use && slot->serial == id) {
            *status = NGX_HTTP_OK;
            json_object_set_new(root, "transfer",
                dashboard_build_transfer_object(conf, slot, now_ms, 1, 1));
            return root;
        }
    }

    json_object_set_new(root, "error", json_string("not_found"));
    return root;
}

static json_t *
dashboard_build_v1_snapshot(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const xrootd_dashboard_totals_t *totals)
{
    json_t *root, *history, *cache, *cluster;

    root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }

    json_object_set_new(root, "active_transfers", dashboard_build_transfer_rows(now_ms, conf, 1));
    json_object_set_new(root, "tpc_transfers",    dashboard_build_tpc_registry(r->pool));
    json_object_set_new(root, "protocols",        dashboard_build_protocols(now_ms, totals));

    cache = json_object();
    if (cache) {
        dashboard_fill_cache(cache);
        json_object_set_new(root, "cache", cache);
    }

    cluster = json_object();
    if (cluster) {
        dashboard_fill_cluster(cluster, r->pool, now_ms, conf);
        json_object_set_new(root, "cluster", cluster);
    }

    json_object_set_new(root, "events", dashboard_build_events(r->pool));

    history = json_object();
    if (history) {
        dashboard_fill_history(history, r->pool);
        json_object_set_new(root, "history", history);
    }

    json_object_set_new(root, "totals", dashboard_build_totals(totals));
    return root;
}

static json_t *
dashboard_build_v1_events(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "events", dashboard_build_events(r->pool));
    return root;
}

static json_t *
dashboard_build_v1_history(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    dashboard_fill_history(root, r->pool);
    return root;
}

static json_t *
dashboard_build_v1_cluster(ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    dashboard_fill_cluster(root, r->pool, now_ms, conf);
    return root;
}

static json_t *
dashboard_build_v1_cache(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    dashboard_fill_cache(root);
    return root;
}

/* Phase 25 — advanced rate-limit zone snapshot. */
static json_t *
dashboard_build_v1_ratelimit(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t            *root = dashboard_new_v1_root(now_ms, conf);
    json_t            *zones_arr;
    xrootd_rl_zone_t  *zones[16];
    ngx_uint_t         nz, zi;

    if (!root) { return NULL; }
    zones_arr = json_array();
    if (zones_arr == NULL) { json_decref(root); return NULL; }

    nz = xrootd_rl_zones_all(zones, 16);
    for (zi = 0; zi < nz; zi++) {
        /* `snap` is static to keep this large (per-principal) buffer off the
         * worker stack. Safe: nginx workers are single-threaded for request
         * processing, so there is no concurrent reuse within this loop. */
        static xrootd_rl_snapshot_entry_t  snap[256];
        ngx_uint_t                         count = 0, i;
        json_t                            *zo = json_object();
        json_t                            *parr = json_array();

        if (zo == NULL || parr == NULL) {
            if (zo) json_decref(zo);
            if (parr) json_decref(parr);
            continue;
        }

        xrootd_rl_snapshot(zones[zi], snap, 256, &count);

        json_object_set_new(zo, "zone",
            json_stringn((const char *) zones[zi]->name.data,
                         zones[zi]->name.len));
        json_object_set_new(zo, "size_bytes",
            json_integer((json_int_t) zones[zi]->size));
        json_object_set_new(zo, "node_count", json_integer((json_int_t) count));

        for (i = 0; i < count; i++) {
            json_t *p = json_object();
            if (p == NULL) { continue; }
            json_object_set_new(p, "key", json_string(snap[i].key_str));
            json_object_set_new(p, "req_total",
                json_integer((json_int_t) snap[i].req_total));
            json_object_set_new(p, "bytes_total",
                json_integer((json_int_t) snap[i].bytes_total));
            json_object_set_new(p, "throttle_count",
                json_integer((json_int_t) snap[i].throttle_count));
            json_object_set_new(p, "req_excess",
                json_integer((json_int_t) snap[i].req_excess));
            json_object_set_new(p, "bw_excess",
                json_integer((json_int_t) snap[i].bw_excess));
            json_array_append_new(parr, p);
        }
        json_object_set_new(zo, "principals", parr);
        json_array_append_new(zones_arr, zo);
    }

    json_object_set_new(root, "zones", zones_arr);
    return root;
}

static json_t *
dashboard_build_v1_not_found(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "error", json_string("not_found"));
    return root;
}

static json_t *
dashboard_build_v1_truncated(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "error", json_string("truncated"));
    return root;
}

/* -------------------------------------------------------------------------
 * Response serialiser
 *
 * Ownership: dashboard_send_json() takes ownership of root and calls
 * json_decref() after the fill — callers must not touch root afterwards.
 * ---------------------------------------------------------------------- */

static ngx_int_t
dashboard_send_json(ngx_http_request_t *r, ngx_int_t status, json_t *root)
{
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_table_elt_t *cc;
    ngx_int_t        rc;
    size_t           needed;
    u_char          *buf;

    /* Two-pass serialise: first call with a NULL buffer returns the exact byte
     * count, then allocate that and dump for real — sizes the response to the
     * payload instead of a fixed scratch buffer. needed==0 means a dump error. */
    needed = json_dumpb(root, NULL, 0, JSON_COMPACT);
    if (needed == 0) {
        json_decref(root);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf = ngx_palloc(r->pool, needed);
    if (buf == NULL) {
        json_decref(root);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    json_dumpb(root, (char *) buf, needed, JSON_COMPACT);
    /* root is fully serialised into buf; release it now (we own the ref). */
    json_decref(root);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    b->pos = b->start = buf;
    b->last = b->end  = buf + needed;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status            = status;
    r->headers_out.content_length_n  = (off_t) needed;
    r->headers_out.content_type      = (ngx_str_t) ngx_string("application/json");
    r->headers_out.content_type_len  = r->headers_out.content_type.len;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc != NULL) {
        cc->hash = 1;
        ngx_str_set(&cc->key,   "Cache-Control");
        ngx_str_set(&cc->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { return rc; }

    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/*
 * WHAT: Entry point for every JSON dashboard endpoint.
 * HOW:  Enforce auth FIRST (before touching SHM or building any payload), reject
 *       non-GET/HEAD, sample the history ring once, collect totals, then dispatch
 *       to the per-endpoint builder. A NULL builder result means OOM/truncation:
 *       we degrade to a 507 "truncated" body and log a dashboard event rather
 *       than emitting a partial document.
 */
ngx_int_t
ngx_http_xrootd_dashboard_api_handler(ngx_http_request_t *r,
    xrootd_dashboard_api_endpoint_e endpoint)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    xrootd_dashboard_totals_t             totals;
    json_t                               *root = NULL;
    int64_t                               now_ms;
    ngx_int_t                             status = NGX_HTTP_OK;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);

    {
        ngx_int_t auth_rc = ngx_http_xrootd_dashboard_check_auth(r, conf);
        if (auth_rc != NGX_OK) { return auth_rc; }
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    now_ms = (int64_t) ngx_current_msec;
    xrootd_dashboard_history_sample(now_ms);
    dashboard_collect_totals(&totals);

    switch (endpoint) {
    case XROOTD_DASHBOARD_API_COMPAT_TRANSFERS:
        root = dashboard_build_compat_transfers(now_ms, conf, &totals);
        break;
    case XROOTD_DASHBOARD_API_V1_TRANSFERS:
        root = dashboard_build_v1_transfers(r, now_ms, conf, &totals);
        break;
    case XROOTD_DASHBOARD_API_V1_TRANSFER_DETAIL:
        root = dashboard_build_v1_transfer_detail(r, now_ms, conf, &status);
        break;
    case XROOTD_DASHBOARD_API_V1_SNAPSHOT:
        root = dashboard_build_v1_snapshot(r, now_ms, conf, &totals);
        break;
    case XROOTD_DASHBOARD_API_V1_EVENTS:
        root = dashboard_build_v1_events(r, now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_HISTORY:
        root = dashboard_build_v1_history(r, now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_CLUSTER:
        root = dashboard_build_v1_cluster(r, now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_CACHE:
        root = dashboard_build_v1_cache(now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_RATELIMIT:
        root = dashboard_build_v1_ratelimit(now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_NOT_FOUND:
    default:
        status = NGX_HTTP_NOT_FOUND;
        root = dashboard_build_v1_not_found(now_ms, conf);
        break;
    }

    if (root == NULL) {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_DASHBOARD, 0, 507,
                                   "dashboard JSON response truncated", NULL);
        status = NGX_HTTP_INSUFFICIENT_STORAGE;
        root   = dashboard_build_v1_truncated(now_ms, conf);
    }

    return dashboard_send_json(r, status, root);
}
