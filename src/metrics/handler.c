#include "metrics_internal.h"


/*
 * Shared metrics zone — allocated by the stream module postconfiguration and
 * read here at request time.  NULL until the stream {} block is processed.
 */
ngx_shm_zone_t *ngx_xrootd_shm_zone = NULL;


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
