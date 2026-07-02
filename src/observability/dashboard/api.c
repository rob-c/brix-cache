/*
 * api.c - (kept) routing + shared helpers
 * Phase-38 split of api.c; behavior-identical.
 */
#include "dashboard_api_internal.h"

const char *
dashboard_direction_name(uint8_t direction)
{
    switch (direction) {
    case XROOTD_XFER_DIR_WRITE: return "write";
    case XROOTD_XFER_DIR_TPC:   return "tpc";
    default:                    return "read";
    }
}


const char *
dashboard_proto_name(uint8_t proto)
{
    switch (proto) {
    case XROOTD_XFER_PROTO_WEBDAV: return "webdav";
    case XROOTD_XFER_PROTO_S3:     return "s3";
    case XROOTD_XFER_PROTO_CVMFS:  return "cvmfs";
    default:                       return "root";
    }
}


const char *
dashboard_state_name(const ngx_http_xrootd_dashboard_loc_conf_t *conf,
    uint8_t state, int64_t idle_ms, int moving)
{
    if (state == XROOTD_XFER_STATE_ERROR)   { return "error"; }
    if (state == XROOTD_XFER_STATE_CLOSING) { return "closing"; }
    /*
     * A transfer idle past the stalled threshold is normally "stalled".  But a
     * transfer that has moved data overall (moving != 0) and is merely between
     * client-imposed rate-limit bursts — xrdcp --xrate sleeps ~84 s then bursts
     * 8 MiB at 100 kB/s — is making scheduled forward progress, not stuck.  Show
     * it as "throttled" so a paced transfer reads as a steady slow row instead
     * of flapping into the red "stalled" state every inter-burst gap.  The
     * "idle" band (shorter pauses) is unchanged so ordinary transfers that just
     * paused briefly are not mislabelled.
     */
    if (idle_ms >= (int64_t) conf->stalled_threshold_ms) {
        return moving ? "throttled" : "stalled";
    }
    if (idle_ms >= (int64_t) conf->idle_threshold_ms)    { return "idle"; }
    return "active";
}


const char *
dashboard_tpc_protocol_name(ngx_uint_t protocol)
{
    switch (protocol) {
    case XROOTD_TPC_PROTO_STREAM: return "stream";
    case XROOTD_TPC_PROTO_WEBDAV: return "webdav";
    default:                      return "unknown";
    }
}


const char *
dashboard_tpc_direction_name(ngx_uint_t direction)
{
    switch (direction) {
    case XROOTD_TPC_DIR_PUSH: return "push";
    case XROOTD_TPC_DIR_PULL: return "pull";
    default:                  return "unknown";
    }
}


const char *
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


const char *
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
uint32_t
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


/* Average bytes/sec over a transfer's lifetime. Guards against a zero/negative
 * elapsed window (clock not advanced, or start in the future) to avoid divide-
 * by-zero; the *1000 converts the ms denominator to a per-second rate. */
uint64_t
dashboard_avg_bps(int64_t bytes, int64_t start_ms, int64_t now_ms)
{
    int64_t elapsed_ms;

    elapsed_ms = (start_ms > 0 && now_ms > start_ms) ? now_ms - start_ms : 0;
    return elapsed_ms > 0 ? (uint64_t) ((bytes * 1000) / elapsed_ms) : 0;
}



/*
 * WHAT: Entry point for every JSON dashboard endpoint.
 * HOW:  Enforce auth FIRST (before touching SHM or building any payload), reject
 *       non-GET/HEAD, sample the history ring once, collect totals, then dispatch
 *       to the per-endpoint builder. A NULL builder result means OOM/truncation:
 *       we degrade to a 507 "truncated" body and log a dashboard event rather
 *       than emitting a partial document.
 */
/*
 * Read-only endpoints that may be served to an unauthenticated viewer (with all
 * PII/secrets redacted) when xrootd_dashboard_anonymous is on. Transfer-detail
 * (session hash + per-op counters) is deliberately NOT here — it stays
 * auth-only; config download and the admin API are separate handlers entirely.
 */
ngx_uint_t
dashboard_endpoint_is_anon_allowed(xrootd_dashboard_api_endpoint_e e)
{
    switch (e) {
    case XROOTD_DASHBOARD_API_COMPAT_TRANSFERS:
    case XROOTD_DASHBOARD_API_V1_TRANSFERS:
    case XROOTD_DASHBOARD_API_V1_SNAPSHOT:
    case XROOTD_DASHBOARD_API_V1_EVENTS:
    case XROOTD_DASHBOARD_API_V1_HISTORY:
    case XROOTD_DASHBOARD_API_V1_CLUSTER:
    case XROOTD_DASHBOARD_API_V1_CACHE:
    case XROOTD_DASHBOARD_API_V1_RATELIMIT:
    case XROOTD_DASHBOARD_API_V1_NOT_FOUND:
        return 1;
    case XROOTD_DASHBOARD_API_V1_TRANSFER_DETAIL:
    default:
        return 0;
    }
}


ngx_int_t
ngx_http_xrootd_dashboard_api_handler(ngx_http_request_t *r,
    xrootd_dashboard_api_endpoint_e endpoint)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    xrootd_dashboard_totals_t             totals;
    json_t                               *root = NULL;
    int64_t                               now_ms;
    ngx_int_t                             status = NGX_HTTP_OK;
    ngx_uint_t                            redact = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);

    /* Three-way auth gate. Authenticated -> full payload. Unauthenticated but
     * xrootd_dashboard_anonymous is on AND this is an anon-allowed read endpoint
     * -> serve a PII/secret-redacted payload (redact=1). Otherwise -> 401.
     * (check_auth suppresses its "missing cookie" event when anonymous is on,
     * so anonymous polls do not spam the event ring.) */
    {
        ngx_int_t auth_rc = ngx_http_xrootd_dashboard_check_auth(r, conf,
                                                                 conf->anonymous);
        if (auth_rc == NGX_OK) {
            redact = 0;
        } else if (conf->anonymous
                   && dashboard_endpoint_is_anon_allowed(endpoint)) {
            redact = 1;
        } else {
            return auth_rc;
        }
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    now_ms = (int64_t) ngx_current_msec;
    xrootd_dashboard_history_sample(now_ms);
    dashboard_collect_totals(&totals);

    switch (endpoint) {
    case XROOTD_DASHBOARD_API_COMPAT_TRANSFERS:
        root = dashboard_build_compat_transfers(now_ms, conf, &totals, redact);
        break;
    case XROOTD_DASHBOARD_API_V1_TRANSFERS:
        root = dashboard_build_v1_transfers(r, now_ms, conf, &totals, redact);
        break;
    case XROOTD_DASHBOARD_API_V1_TRANSFER_DETAIL:
        root = dashboard_build_v1_transfer_detail(r, now_ms, conf, &status);
        break;
    case XROOTD_DASHBOARD_API_V1_SNAPSHOT:
        root = dashboard_build_v1_snapshot(r, now_ms, conf, &totals, redact);
        break;
    case XROOTD_DASHBOARD_API_V1_EVENTS:
        root = dashboard_build_v1_events(r, now_ms, conf, redact);
        break;
    case XROOTD_DASHBOARD_API_V1_HISTORY:
        root = dashboard_build_v1_history(r, now_ms, conf, redact);
        break;
    case XROOTD_DASHBOARD_API_V1_CLUSTER:
        root = dashboard_build_v1_cluster(r, now_ms, conf, redact);
        break;
    case XROOTD_DASHBOARD_API_V1_CACHE:
        root = dashboard_build_v1_cache(now_ms, conf, redact);
        break;
    case XROOTD_DASHBOARD_API_V1_RATELIMIT:
        root = dashboard_build_v1_ratelimit(now_ms, conf, redact);
        break;
    case XROOTD_DASHBOARD_API_V1_NOT_FOUND:
    default:
        status = NGX_HTTP_NOT_FOUND;
        root = dashboard_build_v1_not_found(now_ms, conf, redact);
        break;
    }

    if (root == NULL) {
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_DASHBOARD, 0, 507,
                                   "dashboard JSON response truncated", NULL);
        status = NGX_HTTP_INSUFFICIENT_STORAGE;
        root   = dashboard_build_v1_truncated(now_ms, conf);
    }

    return dashboard_json_send(r, status, root);
}
