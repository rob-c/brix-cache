/*
 * metrics.c - WebDAV request/result accounting helpers.
 */

#include "webdav.h"

ngx_uint_t
webdav_metrics_method(ngx_http_request_t *r)
{
    if (r->method == NGX_HTTP_OPTIONS) {
        return XROOTD_WEBDAV_METHOD_OPTIONS;
    }
    if (r->method == NGX_HTTP_HEAD) {
        return XROOTD_WEBDAV_METHOD_HEAD;
    }
    if (r->method == NGX_HTTP_GET) {
        return XROOTD_WEBDAV_METHOD_GET;
    }
    if (r->method == NGX_HTTP_PUT) {
        return XROOTD_WEBDAV_METHOD_PUT;
    }
    if (r->method == NGX_HTTP_DELETE) {
        return XROOTD_WEBDAV_METHOD_DELETE;
    }
    if (r->method_name.len == 5
        && ngx_strncmp(r->method_name.data, "MKCOL", 5) == 0)
    {
        return XROOTD_WEBDAV_METHOD_MKCOL;
    }
    if (r->method_name.len == 4
        && ngx_strncmp(r->method_name.data, "COPY", 4) == 0)
    {
        return XROOTD_WEBDAV_METHOD_COPY;
    }
    if (r->method_name.len == 8
        && ngx_strncmp(r->method_name.data, "PROPFIND", 8) == 0)
    {
        return XROOTD_WEBDAV_METHOD_PROPFIND;
    }

    return XROOTD_WEBDAV_METHOD_OTHER;
}

static ngx_uint_t
webdav_metrics_status_class(ngx_uint_t status)
{
    if (status >= 100 && status < 200) {
        return XROOTD_HTTP_STATUS_1XX;
    }
    if (status >= 200 && status < 300) {
        return XROOTD_HTTP_STATUS_2XX;
    }
    if (status >= 300 && status < 400) {
        return XROOTD_HTTP_STATUS_3XX;
    }
    if (status >= 400 && status < 500) {
        return XROOTD_HTTP_STATUS_4XX;
    }
    if (status >= 500 && status < 600) {
        return XROOTD_HTTP_STATUS_5XX;
    }

    return XROOTD_HTTP_STATUS_OTHER;
}

void
webdav_metrics_request(ngx_http_request_t *r)
{
    ngx_uint_t method = webdav_metrics_method(r);

    XROOTD_WEBDAV_METRIC_INC(requests_total[method]);
}

void
webdav_metrics_response(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_uint_t method;
    ngx_uint_t status;
    ngx_uint_t status_class;

    if (rc == NGX_DONE) {
        return;
    }

    method = webdav_metrics_method(r);

    if (rc == NGX_ERROR) {
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        status = (ngx_uint_t) rc;
    } else if (r->headers_out.status != 0) {
        status = r->headers_out.status;
    } else {
        status = NGX_HTTP_OK;
    }

    status_class = webdav_metrics_status_class(status);
    XROOTD_WEBDAV_METRIC_INC(responses_total[method][status_class]);
}

ngx_int_t
webdav_metrics_return(ngx_http_request_t *r, ngx_int_t rc)
{
    webdav_metrics_response(r, rc);
    return rc;
}

void
webdav_metrics_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    webdav_metrics_response(r, rc);
    ngx_http_finalize_request(r, rc);
}
