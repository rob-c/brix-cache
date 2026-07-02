/*
 * api_ratelimit.c - extracted concern
 * Phase-38 split of api.c; behavior-identical.
 */
#include "dashboard_api_internal.h"


/* Phase 25 — advanced rate-limit zone snapshot. */
json_t *
dashboard_build_v1_ratelimit(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact)
{
    json_t            *root = dashboard_new_v1_root(now_ms, conf);
    json_t            *zones_arr;
    xrootd_rl_zone_t  *zones[16];
    ngx_uint_t         nz, zi;

    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous", redact ? json_true() : json_false());
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
            /* key_str is the rate-limit principal (DN/VO/IP/path) — drop for anon. */
            if (!redact) {
                json_object_set_new(p, "key", json_string(snap[i].key_str));
            }
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


json_t *
dashboard_build_v1_not_found(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "anonymous", redact ? json_true() : json_false());
    json_object_set_new(root, "error", json_string("not_found"));
    return root;
}


json_t *
dashboard_build_v1_truncated(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    json_t *root = dashboard_new_v1_root(now_ms, conf);
    if (!root) { return NULL; }
    json_object_set_new(root, "error", json_string("truncated"));
    return root;
}
