#include "metrics_internal.h"
#include "compat/http_headers.h"

/* File: metrics handler — Prometheus-format endpoint for nginx-xrootd
 * WHAT: Declares the shared memory zone pointer (ngx_shm_zone_t) allocated by stream module postconfiguration. This global variable is NULL until nginx processes any stream {} block containing xrootd_enable directive. Read here at request time to determine whether metrics data exists — if NULL, handler sends informational message indicating no stream servers configured; otherwise exports all collected metrics via xrootd_export_prometheus_metrics(). */

/*
 * Shared metrics zone — allocated by the stream module postconfiguration and
 * read here at request time.  NULL until the stream {} block is processed.
 */
ngx_shm_zone_t *ngx_xrootd_shm_zone = NULL;

/*
 *
 * WHAT: Handles /metrics HTTP endpoint serving Prometheus-compatible metric output in text/plain format (version=0.0.4, charset=utf-8). Validates metrics enable flag from location config (lcf->enable) — returns NGX_DECLINED if disabled allowing nginx to pass request to other handlers. Restricts access to GET/HEAD methods only via ngx_http_not_allowed() for non-matching HTTP verbs. Discards any request body via ngx_http_discard_request_body() since metrics endpoint has no payload. Initializes metrics writer (mw_init) with nginx request pool allocation — returns 500 Internal Server Error if writer initialization fails. Exports all collected metrics from shared memory zone (ngx_xrootd_shm_zone->data) via xrootd_export_prometheus_metrics() — if shm_zone is NULL sends informational comment indicating no stream servers configured. Finishes metric output with mw_finish(), sets response headers (status=200, content_length=mw.total, content_type=Prometheus text format), and sends final filtered output via ngx_http_output_filter().
 *
 * WHY: Prometheus-compatible metrics endpoint enables external monitoring tools to collect nginx-xrootd performance data without requiring custom instrumentation. The shared memory zone pattern ensures all stream modules (read, write, proxy, TPC) contribute metrics to a single consolidated view — operators can query aggregate statistics across the entire server rather than per-module endpoints. Content type version=0.0.4 follows Prometheus text format specification ensuring compatibility with standard collectors like prometheus-node-exporter and grafana dashboards. NGX_DECLINED return when disabled allows graceful degradation — nginx passes request to other handlers without 404 or error response, enabling operators to toggle metrics visibility without configuration changes. Thread safety: reads only from shared memory zone (allocated once during startup); no shared state modification during metric export. */

ngx_int_t
ngx_http_xrootd_metrics_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_metrics_loc_conf_t *lcf;
    metrics_writer_t                    mw;
    ngx_int_t                           rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_metrics_module);
    if (!lcf->enable) {
        return NGX_DECLINED;
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    xrootd_http_source_offer(r);

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) { return rc; }

    if (mw_init(&mw, r->pool) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_xrootd_shm_zone == NULL || ngx_xrootd_shm_zone->data == NULL) {
        mw_printf(&mw, "# nginx-xrootd: no stream servers configured\n");
    } else {
        xrootd_export_prometheus_metrics(&mw, ngx_xrootd_shm_zone->data);
    }

    /* Phase 20: per-zone KV cache / rate-limit counters (module-global). */
    xrootd_kv_metrics_emit(&mw);

    /* Phase 63 C-7: composed storage-stack info per export. */
    xrootd_storage_backend_metrics_emit(&mw);

    mw_finish(&mw);

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) mw.total;

    {
        ngx_str_t ct = ngx_string(
            "text/plain; version=0.0.4; charset=utf-8");
        r->headers_out.content_type         = ct;
        r->headers_out.content_type_len     = ct.len;
        r->headers_out.content_type_lowcase = NULL;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, mw.head);
}
