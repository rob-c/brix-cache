#include "metrics_internal.h"
#include "core/http/http_headers.h"

/* File: metrics handler — Prometheus-format endpoint for nginx-xrootd
 *
 * WHAT: Declares shared memory zone pointer (ngx_shm_zone_t) allocated by
 *       stream module postconfiguration.
 *       - NULL until nginx processes stream {} block with brix_enable
 *       - Read at request time to determine if metrics data exists
 *       - If NULL: handler sends informational message (no stream servers)
 *       - If set: exports all collected metrics via brix_export_prometheus_metrics()
 */

/*
 * Shared metrics zone — allocated by the stream module postconfiguration and
 * read here at request time.  NULL until the stream {} block is processed.
 * Encapsulated — access via brix_metrics_get_shm_zone().
 */
static ngx_shm_zone_t *ngx_brix_shm_zone = NULL;

/*
 * brix_metrics_get_shm_zone — accessor for metrics SHM zone.
 */
ngx_shm_zone_t *
brix_metrics_get_shm_zone(void)
{
    return ngx_brix_shm_zone;
}

/*
 * WHAT: Handles /metrics HTTP endpoint serving Prometheus-compatible metrics.
 *       - Format: text/plain; version=0.0.4; charset=utf-8
 *       - Validates metrics enable flag (lcf->enable)
 *         → NGX_DECLINED if disabled (nginx passes to other handlers)
 *       - Restricts access to GET/HEAD methods only
 *         → ngx_http_not_allowed() for non-matching verbs
 *       - Discards request body via ngx_http_discard_request_body()
 *       - Initializes metrics writer (mw_init) with nginx request pool
 *         → returns 500 if writer init fails
 *       - Exports metrics from shared memory zone via brix_export_prometheus_metrics()
 *         → if shm_zone NULL: sends informational comment
 *       - Finishes output with mw_finish(), sets response headers:
 *         status=200, content_length=mw.total, content_type=Prometheus format
 *       - Sends final filtered output via ngx_http_output_filter()
 *
 * WHY: Prometheus-compatible endpoint enables external monitoring tools to collect
 *      nginx-xrootd performance data without custom instrumentation.
 *      Shared memory zone pattern ensures all stream modules (read, write, proxy,
 *      TPC) contribute to single consolidated view — operators query aggregate
 *      statistics across entire server rather than per-module endpoints.
 *      Content type version=0.0.4 follows Prometheus text format specification
 *      (compatibility with prometheus-node-exporter, grafana dashboards).
 *      NGX_DECLINED when disabled allows graceful degradation — nginx passes
 *      request to other handlers without 404/error, enabling operators to toggle
 *      metrics visibility without configuration changes.
 *      Thread safety: reads only from shared memory zone (allocated once during
 *      startup); no shared state modification during metric export.
 */

ngx_int_t
ngx_http_brix_metrics_handler(ngx_http_request_t *r)
{
    ngx_http_brix_metrics_loc_conf_t *lcf;
    metrics_writer_t                    mw;
    ngx_int_t                           rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_metrics_module);
    if (!lcf->enable) {
        return NGX_DECLINED;
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    brix_http_source_offer(r);

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) { return rc; }

    if (mw_init(&mw, r->pool) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_brix_shm_zone == NULL || ngx_brix_shm_zone->data == NULL) {
        mw_printf(&mw, "# nginx-xrootd: no stream servers configured\n");
    } else {
        brix_export_prometheus_metrics(&mw, ngx_brix_shm_zone->data);
    }

    /* Phase 20: per-zone KV cache / rate-limit counters (module-global). */
    brix_kv_metrics_emit(&mw);

    /* Phase 63 C-7: composed storage-stack info per export. */
    brix_storage_backend_metrics_emit(&mw);

    /* Phase 116: runtime-DNS target registry (per-worker view). */
    brix_dns_metrics_emit(&mw);

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
