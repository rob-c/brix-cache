/*
 * dashboard_api_internal.h - private split contract for api.c and its Phase-38 siblings.
 * Not a public API: include only from src/dashboard/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_DASHBOARD_API_INTERNAL_H
#define XROOTD_DASHBOARD_API_INTERNAL_H

#include "dashboard_http.h"
#include "dashboard_json.h"
#include "compat/fs_usage.h"
#include "manager/registry.h"
#include "tpc/common/registry.h"
#include "ratelimit/ratelimit.h"
#include <stdio.h>
#include <string.h>
#include <jansson.h>
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


/* api.c */
const char * dashboard_direction_name(uint8_t direction);
const char * dashboard_proto_name(uint8_t proto);
const char * dashboard_state_name(const ngx_http_xrootd_dashboard_loc_conf_t *conf, uint8_t state, int64_t idle_ms, int moving);
const char * dashboard_tpc_protocol_name(ngx_uint_t protocol);
const char * dashboard_tpc_direction_name(ngx_uint_t direction);
const char * dashboard_tpc_state_name(ngx_uint_t state);
const char * dashboard_event_class_name(uint8_t class_id);
uint32_t dashboard_session_hash(const u_char sessid[16]);

/* api_snapshot.c */
void dashboard_collect_totals(xrootd_dashboard_totals_t *totals);

/* api.c */
uint64_t dashboard_avg_bps(int64_t bytes, int64_t start_ms, int64_t now_ms);

/* api_snapshot.c */
void dashboard_collect_protocols(xrootd_dashboard_protocols_t *out, int64_t now_ms);
json_t * dashboard_build_limits(const ngx_http_xrootd_dashboard_loc_conf_t *conf);
json_t * dashboard_build_totals(const xrootd_dashboard_totals_t *totals);

/* api_transfers.c */
json_t * dashboard_build_transfer_object( const ngx_http_xrootd_dashboard_loc_conf_t *conf, const xrootd_transfer_slot_t *slot, int64_t now_ms, ngx_uint_t v1_fields, ngx_uint_t detail_fields, ngx_uint_t redact);
json_t * dashboard_build_transfer_rows(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t v1_fields, ngx_uint_t redact);
json_t * dashboard_build_tpc_registry(ngx_pool_t *pool, ngx_uint_t redact);

/* api_snapshot.c */
json_t * dashboard_build_proto_summary(const xrootd_dashboard_proto_summary_t *s, uint64_t bytes_rx, uint64_t bytes_tx);
json_t * dashboard_build_protocols(int64_t now_ms, const xrootd_dashboard_totals_t *totals);
json_t * dashboard_build_events(ngx_pool_t *pool, ngx_uint_t redact);
void dashboard_fill_history(json_t *target, ngx_pool_t *pool);
void dashboard_fill_cache(json_t *target, ngx_uint_t redact);
void dashboard_fill_cluster(json_t *target, ngx_pool_t *pool, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_new_v1_root(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf);

/* api_transfers.c */
json_t * dashboard_build_compat_transfers(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, const xrootd_dashboard_totals_t *totals, ngx_uint_t redact);
json_t * dashboard_build_v1_transfers(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, const xrootd_dashboard_totals_t *totals, ngx_uint_t redact);
ngx_int_t dashboard_parse_detail_id(ngx_http_request_t *r, uint32_t *id);
json_t * dashboard_build_v1_transfer_detail(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_int_t *status);

/* api_snapshot.c */
json_t * dashboard_build_v1_snapshot(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, const xrootd_dashboard_totals_t *totals, ngx_uint_t redact);
json_t * dashboard_build_v1_events(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_history(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_cluster(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_cache(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);

/* api_ratelimit.c */
json_t * dashboard_build_v1_ratelimit(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_not_found(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_truncated(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf);

/* api.c */
ngx_uint_t dashboard_endpoint_is_anon_allowed(xrootd_dashboard_api_endpoint_e e);

#endif /* XROOTD_DASHBOARD_API_INTERNAL_H */
