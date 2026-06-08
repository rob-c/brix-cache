#include "dashboard_http.h"

#include "../compat/fs_usage.h"
#include "../manager/registry.h"
#include "../tpc/common/registry.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * dashboard/api.c - dashboard JSON endpoints.
 *
 * /xrootd/transfers keeps its original shape.  /xrootd/api/v1/...
 * exposes the richer, schema-tagged dashboard API used by the enhanced page
 * and external tooling.
 */

#define JSON_BUF_SIZE        (1024 * 1024)
#define STALE_GC_MS          600000
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

static char *
json_append(char *p, char *end, const char *fmt, ...)
{
    va_list ap;
    int     n;
    size_t  avail;

    if (p >= end) {
        return end;
    }

    avail = (size_t) (end - p + 1);
    va_start(ap, fmt);
    n = vsnprintf(p, avail, fmt, ap);
    va_end(ap);

    if (n < 0) {
        return p;
    }

    if ((size_t) n >= avail) {
        return end;
    }

    return p + n;
}

static char *
json_append_escaped_str(char *p, char *end, const char *s)
{
    const unsigned char *src;

    if (p >= end) {
        return end;
    }

    *p++ = '"';

    if (s == NULL) {
        if (p < end) {
            *p++ = '"';
        }
        return p;
    }

    src = (const unsigned char *) s;
    while (*src != '\0' && p < end - 1) {
        unsigned char c = *src++;

        if (c == '"' || c == '\\') {
            if ((size_t) (end - p + 1) < 3) {
                return end;
            }
            *p++ = '\\';
            *p++ = (char) c;
            continue;
        }

        if (c < 0x20) {
            if ((size_t) (end - p + 1) < 7) {
                return end;
            }
            p = json_append(p, end, "\\u%04x", (unsigned int) c);
            continue;
        }

        *p++ = (char) c;
    }

    if (p < end) {
        *p++ = '"';
    }

    return p;
}

static const char *
dashboard_direction_name(uint8_t direction)
{
    switch (direction) {
    case XROOTD_XFER_DIR_WRITE:
        return "write";
    case XROOTD_XFER_DIR_TPC:
        return "tpc";
    default:
        return "read";
    }
}

static const char *
dashboard_proto_name(uint8_t proto)
{
    switch (proto) {
    case XROOTD_XFER_PROTO_WEBDAV:
        return "webdav";
    case XROOTD_XFER_PROTO_S3:
        return "s3";
    default:
        return "root";
    }
}

static const char *
dashboard_state_name(const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    uint8_t state, int64_t idle_ms)
{
    if (state == XROOTD_XFER_STATE_ERROR) {
        return "error";
    }
    if (state == XROOTD_XFER_STATE_CLOSING) {
        return "closing";
    }
    if (idle_ms >= (int64_t) conf->stalled_threshold_ms) {
        return "stalled";
    }
    if (idle_ms >= (int64_t) conf->idle_threshold_ms) {
        return "idle";
    }
    return "active";
}

static const char *
dashboard_tpc_protocol_name(ngx_uint_t protocol)
{
    switch (protocol) {
    case XROOTD_TPC_PROTO_STREAM:
        return "stream";
    case XROOTD_TPC_PROTO_WEBDAV:
        return "webdav";
    default:
        return "unknown";
    }
}

static const char *
dashboard_tpc_direction_name(ngx_uint_t direction)
{
    switch (direction) {
    case XROOTD_TPC_DIR_PUSH:
        return "push";
    case XROOTD_TPC_DIR_PULL:
        return "pull";
    default:
        return "unknown";
    }
}

static const char *
dashboard_tpc_state_name(ngx_uint_t state)
{
    switch (state) {
    case XROOTD_TPC_STATE_PENDING:
        return "pending";
    case XROOTD_TPC_STATE_ACTIVE:
        return "active";
    case XROOTD_TPC_STATE_DONE:
        return "done";
    case XROOTD_TPC_STATE_ERROR:
        return "error";
    default:
        return "unknown";
    }
}

static const char *
dashboard_event_class_name(uint8_t class_id)
{
    switch (class_id) {
    case XROOTD_DASH_EVENT_AUTH:
        return "auth";
    case XROOTD_DASH_EVENT_NAMESPACE:
        return "namespace";
    case XROOTD_DASH_EVENT_IO:
        return "io";
    case XROOTD_DASH_EVENT_TPC:
        return "tpc";
    case XROOTD_DASH_EVENT_DASHBOARD:
        return "dashboard";
    default:
        return "unknown";
    }
}

static uint32_t
dashboard_session_hash(const u_char sessid[16])
{
    uint32_t h = 2166136261u;
    ngx_uint_t i;

    for (i = 0; i < 16; i++) {
        h ^= sessid[i];
        h *= 16777619u;
    }

    return h;
}

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

static uint64_t
dashboard_avg_bps(int64_t bytes, int64_t start_ms, int64_t now_ms)
{
    int64_t elapsed_ms;

    elapsed_ms = (start_ms > 0 && now_ms > start_ms) ? now_ms - start_ms : 0;
    return elapsed_ms > 0 ? (uint64_t) ((bytes * 1000) / elapsed_ms) : 0;
}

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

        if (slot->in_use == 0) {
            continue;
        }

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
        avg_bps = dashboard_avg_bps((int64_t) slot->bytes,
                                    slot->start_ms, now_ms);
        if (slot->direction == XROOTD_XFER_DIR_WRITE) {
            summary->ingress_bps += avg_bps;
        } else {
            summary->egress_bps += avg_bps;
        }
    }
}

static char *
dashboard_append_limits(char *p, char *end,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    return json_append(p, end,
        "\"limits\":{"
        "\"max_active_transfers\":%d,"
        "\"max_tpc_registry_transfers\":%d,"
        "\"max_tpc_transfer_rows\":%d,"
        "\"max_recent_events\":%d,"
        "\"history_bucket_seconds\":%d,"
        "\"idle_threshold_ms\":%d,"
        "\"stalled_threshold_ms\":%d"
        "}",
        XROOTD_DASHBOARD_MAX_TRANSFERS,
        XROOTD_TPC_REGISTRY_SLOTS,
        TPC_REGISTRY_JSON_LIMIT,
        XROOTD_DASHBOARD_MAX_EVENTS,
        XROOTD_DASHBOARD_HISTORY_INTERVAL_MS / 1000,
        (int) conf->idle_threshold_ms,
        (int) conf->stalled_threshold_ms);
}

static char *
dashboard_append_totals(char *p, char *end,
    const xrootd_dashboard_totals_t *totals)
{
    return json_append(p, end,
        "\"totals\":{"
        "\"connections_active\":%" PRIu64 ","
        "\"connections_total\":%" PRIu64 ","
        "\"bytes_rx_total\":%" PRIu64 ","
        "\"bytes_tx_total\":%" PRIu64 ","
        "\"webdav_bytes_rx\":%" PRIu64 ","
        "\"webdav_bytes_tx\":%" PRIu64 ","
        "\"s3_bytes_rx\":%" PRIu64 ","
        "\"s3_bytes_tx\":%" PRIu64 ","
        "\"stream_errors_total\":%" PRIu64 ","
        "\"webdav_errors_total\":%" PRIu64 ","
        "\"s3_errors_total\":%" PRIu64
        "}",
        totals->conn_active, totals->conn_total,
        totals->bytes_rx, totals->bytes_tx,
        totals->wdav_rx, totals->wdav_tx,
        totals->s3_rx, totals->s3_tx,
        totals->stream_errors, totals->webdav_errors, totals->s3_errors);
}

static char *
dashboard_append_transfer_object(char *p, char *end,
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

    ngx_memory_barrier();

    last_ms = (int64_t) slot->last_ms;
    bytes = (int64_t) slot->bytes;
    start_ms = slot->start_ms;
    idle_ms = (last_ms > 0 && now_ms >= last_ms) ? now_ms - last_ms : 0;
    avg_bps = dashboard_avg_bps(bytes, start_ms, now_ms);
    instant_bps = (uint64_t) slot->instant_bps;

    ngx_memcpy(client_ip, slot->client_ip, sizeof(client_ip));
    ngx_memcpy(identity, slot->identity, sizeof(identity));
    ngx_memcpy(vo, slot->vo, sizeof(vo));
    ngx_memcpy(path, slot->path, sizeof(path));
    ngx_memcpy(op, slot->op, sizeof(op));
    ngx_memcpy(last_error, slot->last_error, sizeof(last_error));
    ngx_memcpy(remote_host, slot->tpc_remote_host, sizeof(remote_host));
    ngx_memcpy(remote_path, slot->tpc_remote_path_hint, sizeof(remote_path));
    client_ip[sizeof(client_ip) - 1] = '\0';
    identity[sizeof(identity) - 1] = '\0';
    vo[sizeof(vo) - 1] = '\0';
    path[sizeof(path) - 1] = '\0';
    op[sizeof(op) - 1] = '\0';
    last_error[sizeof(last_error) - 1] = '\0';
    remote_host[sizeof(remote_host) - 1] = '\0';
    remote_path[sizeof(remote_path) - 1] = '\0';

    p = json_append(p, end, "{\"id\":%u,\"client\":", slot->serial);
    p = json_append_escaped_str(p, end, client_ip);
    p = json_append(p, end, ",\"identity\":");
    p = json_append_escaped_str(p, end, identity);
    p = json_append(p, end, ",\"path\":");
    p = json_append_escaped_str(p, end, path);
    p = json_append(p, end,
                    ",\"direction\":\"%s\""
                    ",\"protocol\":\"%s\""
                    ",\"bytes\":%" PRId64
                    ",\"start_ms\":%" PRId64
                    ",\"last_ms\":%" PRId64,
                    dashboard_direction_name(slot->direction),
                    dashboard_proto_name(slot->proto),
                    bytes, start_ms, last_ms);

    if (!v1_fields) {
        return json_append(p, end, "}");
    }

    p = json_append(p, end, ",\"worker_pid\":%ld", (long) slot->worker_pid);
    p = json_append(p, end, ",\"vo\":");
    p = json_append_escaped_str(p, end, vo);
    p = json_append(p, end, ",\"op\":");
    p = json_append_escaped_str(p, end, op);
    p = json_append(p, end,
                    ",\"state\":\"%s\""
                    ",\"expected_bytes\":%" PRId64
                    ",\"instant_bps\":%" PRIu64
                    ",\"avg_bps\":%" PRIu64
                    ",\"idle_ms\":%" PRId64
                    ",\"state_since_ms\":%" PRId64
                    ",\"last_error\":",
                    dashboard_state_name(conf, slot->state, idle_ms),
                    slot->expected_bytes,
                    instant_bps,
                    avg_bps,
                    idle_ms,
                    (int64_t) slot->state_since_ms);
    p = json_append_escaped_str(p, end, last_error);

    if (slot->direction == XROOTD_XFER_DIR_TPC
        || remote_host[0] != '\0' || remote_path[0] != '\0')
    {
        p = json_append(p, end, ",\"tpc\":{\"remote_host\":");
        p = json_append_escaped_str(p, end, remote_host);
        p = json_append(p, end, ",\"path_hint\":");
        p = json_append_escaped_str(p, end, remote_path);
        p = json_append(p, end,
                        ",\"remote_status\":%d,\"curl_exit\":%d}",
                        slot->tpc_remote_status, slot->tpc_curl_exit);
    }

    if (detail_fields) {
        p = json_append(p, end,
                        ",\"session_hash\":\"%08x\""
                        ",\"counters\":{"
                        "\"read_ops\":%ld,"
                        "\"write_ops\":%ld,"
                        "\"sync_ops\":%ld,"
                        "\"close_ops\":%ld"
                        "}",
                        dashboard_session_hash(slot->sessid),
                        (long) slot->read_ops,
                        (long) slot->write_ops,
                        (long) slot->sync_ops,
                        (long) slot->close_ops);
    }

    return json_append(p, end, "}");
}

static char *
dashboard_append_transfer_rows(char *p, char *end, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t v1_fields)
{
    xrootd_transfer_table_t *tbl;
    ngx_uint_t              first = 1;
    ngx_uint_t              i;

    p = json_append(p, end, "\"active_transfers\":[");

    if (ngx_xrootd_dashboard_shm_zone == NULL
        || ngx_xrootd_dashboard_shm_zone->data == NULL
        || ngx_xrootd_dashboard_shm_zone->data == (void *) 1)
    {
        return json_append(p, end, "]");
    }

    tbl = ngx_xrootd_dashboard_shm_zone->data;
    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS && p < end - 1024; i++) {
        xrootd_transfer_slot_t *slot = &tbl->slots[i];
        int64_t                 last_ms;

        if (slot->in_use == 0) {
            continue;
        }

        last_ms = (int64_t) slot->last_ms;
        if (last_ms > 0 && now_ms - last_ms > STALE_GC_MS) {
            xrootd_dashboard_event_add(XROOTD_DASH_EVENT_DASHBOARD,
                                       slot->proto, 0,
                                       "stale active transfer cleaned up",
                                       slot->path);
            xrootd_transfer_slot_free(tbl, (int) i);
            continue;
        }

        if (!first) {
            p = json_append(p, end, ",");
        }
        first = 0;
        p = dashboard_append_transfer_object(p, end, conf, slot, now_ms,
                                             v1_fields, 0);
    }

    return json_append(p, end, "]");
}

static char *
dashboard_append_tpc_registry(char *p, char *end, ngx_pool_t *pool)
{
    xrootd_tpc_transfer_snapshot_t *rows;
    ngx_uint_t                      n, i;

    p = json_append(p, end, "\"tpc_transfers\":[");

    rows = ngx_pcalloc(pool, sizeof(*rows) * TPC_REGISTRY_JSON_LIMIT);
    if (rows == NULL) {
        return json_append(p, end, "]");
    }

    n = xrootd_tpc_registry_snapshot(rows, TPC_REGISTRY_JSON_LIMIT);
    for (i = 0; i < n && p < end - 1024; i++) {
        if (i != 0) {
            p = json_append(p, end, ",");
        }

        p = json_append(p, end,
                        "{\"id\":%" PRIu64
                        ",\"protocol\":\"%s\""
                        ",\"direction\":\"%s\""
                        ",\"state\":\"%s\""
                        ",\"source\":",
                        rows[i].id,
                        dashboard_tpc_protocol_name(rows[i].protocol),
                        dashboard_tpc_direction_name(rows[i].direction),
                        dashboard_tpc_state_name(rows[i].state));
        p = json_append_escaped_str(p, end, rows[i].src_url);
        p = json_append(p, end, ",\"destination\":");
        p = json_append_escaped_str(p, end, rows[i].dst_path);
        p = json_append(p, end,
                        ",\"bytes_done\":%" PRId64
                        ",\"bytes_total\":%" PRId64
                        ",\"started_at\":%" PRId64
                        ",\"updated_at\":%" PRId64
                        "}",
                        (int64_t) rows[i].bytes_done,
                        (int64_t) rows[i].bytes_total,
                        (int64_t) rows[i].started_at,
                        (int64_t) rows[i].updated_at);
    }

    return json_append(p, end, "]");
}

static char *
dashboard_append_protocols(char *p, char *end, int64_t now_ms,
    const xrootd_dashboard_totals_t *totals)
{
    xrootd_dashboard_protocols_t ps;

    dashboard_collect_protocols(&ps, now_ms);

    return json_append(p, end,
        "\"protocols\":{"
        "\"root\":{\"active\":%u,\"ingress_bps\":%" PRIu64
            ",\"egress_bps\":%" PRIu64 ",\"bytes_rx_total\":%" PRIu64
            ",\"bytes_tx_total\":%" PRIu64 "},"
        "\"webdav\":{\"active\":%u,\"ingress_bps\":%" PRIu64
            ",\"egress_bps\":%" PRIu64 ",\"bytes_rx_total\":%" PRIu64
            ",\"bytes_tx_total\":%" PRIu64 "},"
        "\"s3\":{\"active\":%u,\"ingress_bps\":%" PRIu64
            ",\"egress_bps\":%" PRIu64 ",\"bytes_rx_total\":%" PRIu64
            ",\"bytes_tx_total\":%" PRIu64 "},"
        "\"tpc\":{\"active\":%u,\"ingress_bps\":%" PRIu64
            ",\"egress_bps\":%" PRIu64 "}"
        "}",
        (unsigned) ps.root.active, ps.root.ingress_bps, ps.root.egress_bps,
        totals->bytes_rx, totals->bytes_tx,
        (unsigned) ps.webdav.active, ps.webdav.ingress_bps, ps.webdav.egress_bps,
        totals->wdav_rx, totals->wdav_tx,
        (unsigned) ps.s3.active, ps.s3.ingress_bps, ps.s3.egress_bps,
        totals->s3_rx, totals->s3_tx,
        (unsigned) ps.tpc.active, ps.tpc.ingress_bps, ps.tpc.egress_bps);
}

static char *
dashboard_append_events(char *p, char *end, ngx_pool_t *pool)
{
    xrootd_dashboard_event_t *events;
    ngx_uint_t                n, i;

    events = ngx_pcalloc(pool, sizeof(*events) * XROOTD_DASHBOARD_MAX_EVENTS);
    if (events == NULL) {
        return json_append(p, end, "\"events\":[]");
    }

    n = xrootd_dashboard_events_snapshot(events,
                                         XROOTD_DASHBOARD_MAX_EVENTS);
    p = json_append(p, end, "\"events\":[");
    for (i = 0; i < n && p < end - 512; i++) {
        if (i != 0) {
            p = json_append(p, end, ",");
        }

        p = json_append(p, end,
                        "{\"sequence\":%ld,\"time_ms\":%" PRId64
                        ",\"class\":\"%s\",\"protocol\":\"%s\","
                        "\"status\":%u,\"message\":",
                        (long) events[i].sequence, events[i].time_ms,
                        dashboard_event_class_name(events[i].class_id),
                        dashboard_proto_name(events[i].proto),
                        (unsigned) events[i].status);
        p = json_append_escaped_str(p, end, events[i].message);
        p = json_append(p, end, ",\"path_hint\":");
        p = json_append_escaped_str(p, end, events[i].path_hint);
        p = json_append(p, end, "}");
    }

    return json_append(p, end, "]");
}

static char *
dashboard_append_history(char *p, char *end, ngx_pool_t *pool,
    ngx_uint_t wrapped)
{
    xrootd_dashboard_history_bucket_t *buckets;
    ngx_uint_t                         n, i;

    buckets = ngx_pcalloc(pool, sizeof(*buckets)
                                * XROOTD_DASHBOARD_HISTORY_BUCKETS);
    if (buckets == NULL) {
        return wrapped ? json_append(p, end, "\"history\":{\"buckets\":[]}")
                       : json_append(p, end, "\"buckets\":[]");
    }

    n = xrootd_dashboard_history_snapshot(buckets,
                                          XROOTD_DASHBOARD_HISTORY_BUCKETS);
    if (wrapped) {
        p = json_append(p, end, "\"history\":{");
    }
    p = json_append(p, end, "\"bucket_seconds\":%d,\"buckets\":[",
                    XROOTD_DASHBOARD_HISTORY_INTERVAL_MS / 1000);

    for (i = 0; i < n && p < end - 512; i++) {
        if (i != 0) {
            p = json_append(p, end, ",");
        }

        p = json_append(p, end,
            "{\"time_ms\":%" PRId64
            ",\"active_root\":%ld"
            ",\"active_webdav\":%ld"
            ",\"active_s3\":%ld"
            ",\"active_tpc\":%ld"
            ",\"bytes_rx\":%ld"
            ",\"bytes_tx\":%ld"
            ",\"errors\":%ld"
            ",\"auth_failures\":%ld"
            ",\"write_stalls\":%ld"
            ",\"cache_occupancy_ppm\":%u}",
            buckets[i].bucket_start_ms,
            (long) buckets[i].active_root,
            (long) buckets[i].active_webdav,
            (long) buckets[i].active_s3,
            (long) buckets[i].active_tpc,
            (long) buckets[i].bytes_rx,
            (long) buckets[i].bytes_tx,
            (long) buckets[i].errors,
            (long) buckets[i].auth_failures,
            (long) buckets[i].write_stalls,
            buckets[i].cache_occupancy_ppm);
    }

    p = json_append(p, end, "]");
    return wrapped ? json_append(p, end, "}") : p;
}

static char *
dashboard_append_cache(char *p, char *end, ngx_uint_t wrapped)
{
    ngx_xrootd_metrics_t *met;
    ngx_uint_t            i;
    ngx_uint_t            first = 1;
    ngx_uint_t            enabled = 0;
    uint64_t              wt_dirty = 0;
    uint64_t              wt_pending = 0;
    uint64_t              wt_success = 0;
    uint64_t              wt_errors = 0;
    uint64_t              wt_bytes = 0;

    if (wrapped) {
        p = json_append(p, end, "\"cache\":{");
    }

    if (ngx_xrootd_shm_zone == NULL
        || ngx_xrootd_shm_zone->data == NULL
        || ngx_xrootd_shm_zone->data == (void *) 1)
    {
        p = json_append(p, end,
            "\"enabled\":false,\"listeners\":[],"
            "\"write_through\":{\"enabled\":false,\"dirty_handles\":0,"
            "\"flush_pending\":0,\"flush_success_total\":0,"
            "\"flush_errors_total\":0,\"flush_bytes_total\":0}");
        return wrapped ? json_append(p, end, "}") : p;
    }

    met = ngx_xrootd_shm_zone->data;
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        if (met->servers[i].in_use && met->servers[i].cache_enabled) {
            enabled = 1;
        }
        wt_dirty += (uint64_t) met->servers[i].wt_dirty_handles;
        wt_pending += (uint64_t) met->servers[i].wt_flush_pending;
        wt_success += (uint64_t) met->servers[i].wt_flush_success_total;
        wt_errors += (uint64_t) met->servers[i].wt_flush_error_total;
        wt_bytes += (uint64_t) met->servers[i].wt_flush_bytes_total;
    }

    p = json_append(p, end, "\"enabled\":%s,\"listeners\":[",
                    enabled ? "true" : "false");

    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS && p < end - 768; i++) {
        ngx_xrootd_srv_metrics_t *srv = &met->servers[i];
        xrootd_fs_usage_t         fsu;

        if (!srv->in_use || !srv->cache_enabled) {
            continue;
        }

        if (!first) {
            p = json_append(p, end, ",");
        }
        first = 0;

        p = json_append(p, end,
                        "{\"port\":%u,\"auth\":", (unsigned) srv->port);
        p = json_append_escaped_str(p, end, srv->auth);
        p = json_append(p, end,
                        ",\"eviction_threshold_ratio\":%0.6f"
                        ",\"evictions_total\":%ld"
                        ",\"evicted_bytes_total\":%ld"
                        ",\"eviction_errors_total\":%ld",
                        (double) srv->cache_eviction_threshold / 1000000.0,
                        (long) srv->cache_evictions_total,
                        (long) srv->cache_evicted_bytes_total,
                        (long) srv->cache_eviction_errors_total);

        if (xrootd_fs_usage_stat(srv->cache_root, &fsu) == NGX_OK) {
            p = json_append(p, end,
                            ",\"occupancy_ratio\":%0.6f"
                            ",\"bytes_total\":%" PRIu64
                            ",\"bytes_used\":%" PRIu64
                            ",\"bytes_available\":%" PRIu64,
                            (double) fsu.occupancy_ppm / 1000000.0,
                            fsu.total_bytes, fsu.occupancy_bytes,
                            fsu.available_bytes);
        }

        p = json_append(p, end, "}");
    }

    p = json_append(p, end,
        "],\"write_through\":{\"enabled\":%s,"
        "\"dirty_handles\":%" PRIu64 ","
        "\"flush_pending\":%" PRIu64 ","
        "\"flush_success_total\":%" PRIu64 ","
        "\"flush_errors_total\":%" PRIu64 ","
        "\"flush_bytes_total\":%" PRIu64 "}",
        (wt_dirty || wt_pending || wt_success || wt_errors || wt_bytes)
            ? "true" : "false",
        wt_dirty, wt_pending, wt_success, wt_errors, wt_bytes);
    return wrapped ? json_append(p, end, "}") : p;
}

static char *
dashboard_append_cluster(char *p, char *end, ngx_pool_t *pool, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t wrapped)
{
    xrootd_srv_snapshot_entry_t *entries;
    ngx_uint_t                   n, i;

    entries = ngx_pcalloc(pool, sizeof(*entries) * XROOTD_SRV_REGISTRY_SLOTS);
    if (entries == NULL) {
        return wrapped ? json_append(p, end, "\"cluster\":{\"servers\":[]}")
                       : json_append(p, end, "\"servers\":[]");
    }

    n = xrootd_srv_snapshot(entries, XROOTD_SRV_REGISTRY_SLOTS,
                            (ngx_msec_t) now_ms);

    if (wrapped) {
        p = json_append(p, end, "\"cluster\":{");
    }
    p = json_append(p, end, "\"stale_after_ms\":%d,\"servers\":[",
                    (int) conf->cluster_stale_after_ms);

    for (i = 0; i < n && p < end - 768; i++) {
        int64_t age = now_ms >= (int64_t) entries[i].last_seen
                      ? now_ms - (int64_t) entries[i].last_seen
                      : 0;

        if (i != 0) {
            p = json_append(p, end, ",");
        }

        p = json_append(p, end, "{\"host\":");
        p = json_append_escaped_str(p, end, entries[i].host);
        p = json_append(p, end,
                        ",\"port\":%u,\"paths\":",
                        (unsigned) entries[i].port);
        p = json_append_escaped_str(p, end, entries[i].paths);
        p = json_append(p, end,
                        ",\"free_mb\":%u"
                        ",\"util_pct\":%u"
                        ",\"last_seen\":%" PRId64
                        ",\"heartbeat_age_ms\":%" PRId64
                        ",\"stale\":%s}",
                        entries[i].free_mb,
                        entries[i].util_pct,
                        (int64_t) entries[i].last_seen,
                        age,
                        age > (int64_t) conf->cluster_stale_after_ms
                            ? "true" : "false");
    }

    p = json_append(p, end, "]");
    return wrapped ? json_append(p, end, "}") : p;
}

static char *
dashboard_build_v1_prefix(char *p, char *end, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    p = json_append(p, end,
                    "{\"schema\":\"xrootd-dashboard.v1\","
                    "\"server_ms\":%" PRId64 ",",
                    now_ms);
    p = dashboard_append_limits(p, end, conf);
    return json_append(p, end, ",");
}

static char *
dashboard_build_compat_transfers(char *p, char *end, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const xrootd_dashboard_totals_t *totals)
{
    p = json_append(p, end, "{\"server_ms\":%" PRId64 ",", now_ms);
    p = dashboard_append_transfer_rows(p, end, now_ms, conf, 0);
    p = json_append(p, end, ",");
    p = dashboard_append_totals(p, end, totals);
    return json_append(p, end, "}");
}

static char *
dashboard_build_v1_transfers(char *p, char *end, ngx_http_request_t *r,
    int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const xrootd_dashboard_totals_t *totals)
{
    p = dashboard_build_v1_prefix(p, end, now_ms, conf);
    p = dashboard_append_transfer_rows(p, end, now_ms, conf, 1);
    p = json_append(p, end, ",");
    p = dashboard_append_tpc_registry(p, end, r->pool);
    p = json_append(p, end, ",");
    p = dashboard_append_totals(p, end, totals);
    return json_append(p, end, "}");
}

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

    for (i = prefix_len; i < r->uri.len; i++) {
        u_char c = r->uri.data[i];

        if (c < '0' || c > '9') {
            return NGX_DECLINED;
        }

        value = value * 10u + (uint32_t) (c - '0');
    }

    *id = value;
    return NGX_OK;
}

static char *
dashboard_build_v1_transfer_detail(char *p, char *end, ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    ngx_int_t *status)
{
    xrootd_transfer_table_t *tbl;
    uint32_t                 id;
    ngx_uint_t               i;

    *status = NGX_HTTP_NOT_FOUND;

    p = dashboard_build_v1_prefix(p, end, now_ms, conf);

    if (dashboard_parse_detail_id(r, &id) != NGX_OK) {
        *status = NGX_HTTP_BAD_REQUEST;
        return json_append(p, end, "\"error\":\"bad_transfer_id\"}");
    }

    if (ngx_xrootd_dashboard_shm_zone == NULL
        || ngx_xrootd_dashboard_shm_zone->data == NULL
        || ngx_xrootd_dashboard_shm_zone->data == (void *) 1)
    {
        return json_append(p, end, "\"error\":\"not_found\"}");
    }

    tbl = ngx_xrootd_dashboard_shm_zone->data;
    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
        xrootd_transfer_slot_t *slot = &tbl->slots[i];

        if (slot->in_use && slot->serial == id) {
            *status = NGX_HTTP_OK;
            p = json_append(p, end, "\"transfer\":");
            p = dashboard_append_transfer_object(p, end, conf, slot, now_ms,
                                                 1, 1);
            return json_append(p, end, "}");
        }
    }

    return json_append(p, end, "\"error\":\"not_found\"}");
}

static char *
dashboard_build_v1_snapshot(char *p, char *end, ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    const xrootd_dashboard_totals_t *totals)
{
    p = dashboard_build_v1_prefix(p, end, now_ms, conf);
    p = dashboard_append_transfer_rows(p, end, now_ms, conf, 1);
    p = json_append(p, end, ",");
    p = dashboard_append_tpc_registry(p, end, r->pool);
    p = json_append(p, end, ",");
    p = dashboard_append_protocols(p, end, now_ms, totals);
    p = json_append(p, end, ",");
    p = dashboard_append_cache(p, end, 1);
    p = json_append(p, end, ",");
    p = dashboard_append_cluster(p, end, r->pool, now_ms, conf, 1);
    p = json_append(p, end, ",");
    p = dashboard_append_events(p, end, r->pool);
    p = json_append(p, end, ",");
    p = dashboard_append_history(p, end, r->pool, 1);
    p = json_append(p, end, ",");
    p = dashboard_append_totals(p, end, totals);
    return json_append(p, end, "}");
}

static char *
dashboard_build_v1_events(char *p, char *end, ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    p = dashboard_build_v1_prefix(p, end, now_ms, conf);
    p = dashboard_append_events(p, end, r->pool);
    return json_append(p, end, "}");
}

static char *
dashboard_build_v1_history(char *p, char *end, ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    p = dashboard_build_v1_prefix(p, end, now_ms, conf);
    p = dashboard_append_history(p, end, r->pool, 0);
    return json_append(p, end, "}");
}

static char *
dashboard_build_v1_cluster(char *p, char *end, ngx_http_request_t *r,
    int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    p = dashboard_build_v1_prefix(p, end, now_ms, conf);
    p = dashboard_append_cluster(p, end, r->pool, now_ms, conf, 0);
    return json_append(p, end, "}");
}

static char *
dashboard_build_v1_cache(char *p, char *end, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    p = dashboard_build_v1_prefix(p, end, now_ms, conf);
    p = dashboard_append_cache(p, end, 0);
    return json_append(p, end, "}");
}

static char *
dashboard_build_v1_not_found(char *p, char *end, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    p = dashboard_build_v1_prefix(p, end, now_ms, conf);
    return json_append(p, end, "\"error\":\"not_found\"}");
}

static char *
dashboard_build_v1_truncated(char *p, char *end, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    p = dashboard_build_v1_prefix(p, end, now_ms, conf);
    return json_append(p, end, "\"error\":\"truncated\"}");
}

static ngx_int_t
dashboard_send_json(ngx_http_request_t *r, ngx_int_t status,
    char *buf, char *p)
{
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_table_elt_t *cc;
    ngx_int_t        rc;

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = (u_char *) buf;
    b->last = (u_char *) p;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = status;
    r->headers_out.content_length_n = (off_t) (p - buf);
    r->headers_out.content_type =
        (ngx_str_t) ngx_string("application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc != NULL) {
        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        ngx_str_set(&cc->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

ngx_int_t
ngx_http_xrootd_dashboard_api_handler(ngx_http_request_t *r,
    xrootd_dashboard_api_endpoint_e endpoint)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    xrootd_dashboard_totals_t             totals;
    char                                 *buf, *p, *end;
    int64_t                               now_ms;
    ngx_int_t                             status = NGX_HTTP_OK;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);

    {
        ngx_int_t auth_rc = ngx_http_xrootd_dashboard_check_auth(r, conf);
        if (auth_rc != NGX_OK) {
            return auth_rc;
        }
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    buf = ngx_palloc(r->pool, JSON_BUF_SIZE);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = buf;
    end = buf + JSON_BUF_SIZE - 1;
    now_ms = (int64_t) ngx_current_msec;

    xrootd_dashboard_history_sample(now_ms);
    dashboard_collect_totals(&totals);

    switch (endpoint) {
    case XROOTD_DASHBOARD_API_COMPAT_TRANSFERS:
        p = dashboard_build_compat_transfers(p, end, now_ms, conf, &totals);
        break;
    case XROOTD_DASHBOARD_API_V1_TRANSFERS:
        p = dashboard_build_v1_transfers(p, end, r, now_ms, conf, &totals);
        break;
    case XROOTD_DASHBOARD_API_V1_TRANSFER_DETAIL:
        p = dashboard_build_v1_transfer_detail(p, end, r, now_ms, conf,
                                               &status);
        break;
    case XROOTD_DASHBOARD_API_V1_SNAPSHOT:
        p = dashboard_build_v1_snapshot(p, end, r, now_ms, conf, &totals);
        break;
    case XROOTD_DASHBOARD_API_V1_EVENTS:
        p = dashboard_build_v1_events(p, end, r, now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_HISTORY:
        p = dashboard_build_v1_history(p, end, r, now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_CLUSTER:
        p = dashboard_build_v1_cluster(p, end, r, now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_CACHE:
        p = dashboard_build_v1_cache(p, end, now_ms, conf);
        break;
    case XROOTD_DASHBOARD_API_V1_NOT_FOUND:
    default:
        status = NGX_HTTP_NOT_FOUND;
        p = dashboard_build_v1_not_found(p, end, now_ms, conf);
        break;
    }

    if (p >= end) {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_DASHBOARD, 0, 507,
                                   "dashboard JSON response truncated",
                                   NULL);
        status = NGX_HTTP_INSUFFICIENT_STORAGE;
        p = buf;
        p = dashboard_build_v1_truncated(p, end, now_ms, conf);
    }

    *p = '\0';
    return dashboard_send_json(r, status, buf, p);
}
