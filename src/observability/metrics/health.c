/*
 * health.c — content handler for the `xrootd_health on;` location (phase-47 W2).
 *
 * WHAT: ngx_http_xrootd_health_handler() serves GET/HEAD /healthz as a small
 *   JSON document so an external load balancer or a Kubernetes liveness/
 *   readiness probe has a cheap endpoint to poll.  Liveness is implicit: if
 *   this worker can accept the connection and run the handler it returns 200.
 *   `?verbose` adds cheap, non-secret readiness signals (metrics SHM mapped,
 *   worker pid, nginx version).
 *
 * WHY: The module already exposes /metrics (scrape) and the dashboard, but
 *   neither is a clean probe target — /metrics is a large text body and the
 *   dashboard needs auth.  A dedicated 200/JSON endpoint keeps probes light and
 *   lets an operator wire `livenessProbe: GET /healthz` directly.  It lives in
 *   the metrics module (not a new .so) and mirrors the read-only SRR/metrics
 *   handlers: method-gated, body discarded, no request input affects output.
 *
 * HOW: classify ?verbose → build the JSON in the request pool with ngx_snprintf
 *   (no jansson; the document is tiny and fixed-shape) → set status/headers →
 *   send_header → output the single memory buffer.  HEAD stops after the header.
 *   Reads only process globals (ngx_pid) and the metrics SHM zone pointer; it
 *   never touches the request body and never emits a secret.
 */

#include "metrics_internal.h"
#include "core/compat/http_headers.h"
#include "core/compat/alloc_guard.h"


/* True when the request's query string contains the bare `verbose` flag. */
static ngx_uint_t
health_verbose_requested(ngx_http_request_t *r)
{
    if (r->args.len == 0) {
        return 0;
    }
    return ngx_strnstr(r->args.data, "verbose", r->args.len) != NULL ? 1 : 0;
}


/*
 * Render the health document into a pool buffer.  Non-verbose is a fixed
 * liveness line; verbose appends the readiness object.  Returns the buffer (and
 * its length via *len), or NULL on allocation failure.
 */
static u_char *
health_build_json(ngx_http_request_t *r, ngx_uint_t verbose, size_t *len)
{
    static const size_t   cap = 512;
    u_char               *buf;
    u_char               *p;
    const char           *shm_state;
    ngx_xrootd_metrics_t *m;
    ngx_uint_t            generation = 0;
    uint64_t             config_hash = 0;

    XROOTD_PNALLOC_OR_RETURN(buf, r->pool, cap, NULL);

    /* The metrics SHM zone is created at config time (metrics/config.c) and is
     * the module's shared state — "mapped" once a stream server block exists.
     * When mapped it also carries the config/reload fingerprint published by the
     * master in init_module (xrootd_config_version_publish). */
    m = (ngx_xrootd_shm_zone != NULL) ? ngx_xrootd_shm_zone->data : NULL;
    if (m != NULL) {
        generation  = (ngx_uint_t) m->config_generation;
        config_hash = m->config_hash;
    }

    if (!verbose) {
        /* config_generation/config_version are cheap and reload-relevant, so
         * they ride on the default (non-verbose) document: a probe can confirm a
         * reload took effect without opting into the heavier readiness block. */
        p = ngx_snprintf(buf, cap,
                         "{\"status\":\"ok\",\"service\":\"nginx-xrootd\","
                         "\"config_generation\":%ui,"
                         "\"config_version\":\"%016xL\"}\n",
                         generation, config_hash);
        *len = (size_t) (p - buf);
        return buf;
    }

    shm_state = (m != NULL) ? "mapped" : "unmapped";

    p = ngx_snprintf(buf, cap,
                     "{\"status\":\"ok\",\"service\":\"nginx-xrootd\","
                     "\"config_generation\":%ui,"
                     "\"config_version\":\"%016xL\","
                     "\"checks\":{"
                     "\"metrics_shm\":\"%s\","
                     "\"worker_pid\":%P,"
                     "\"nginx_version\":\"%s\""
                     "}}\n",
                     generation, config_hash,
                     shm_state, ngx_pid, NGINX_VERSION);
    *len = (size_t) (p - buf);
    return buf;
}


ngx_int_t
ngx_http_xrootd_health_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_metrics_loc_conf_t *lcf;
    ngx_int_t                           rc;
    u_char                             *buf;
    size_t                              len;
    ngx_buf_t                          *b;
    ngx_chain_t                         out;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_metrics_module);
    if (!lcf->health) {
        return NGX_DECLINED;
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    xrootd_http_source_offer(r);

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    buf = health_build_json(r, health_verbose_requested(r), &len);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;

    {
        ngx_str_t ct = ngx_string("application/json");
        r->headers_out.content_type         = ct;
        r->headers_out.content_type_len     = ct.len;
        r->headers_out.content_type_lowcase = NULL;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    XROOTD_PCALLOC_OR_RETURN(b, r->pool, sizeof(*b), NGX_HTTP_INTERNAL_SERVER_ERROR);
    b->pos      = b->start = buf;
    b->last     = b->end   = buf + len;
    b->memory   = 1;
    b->last_buf = 1;

    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
