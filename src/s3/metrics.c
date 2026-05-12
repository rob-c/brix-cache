/*
 * metrics.c - S3-compatible endpoint request/result accounting helpers.
 */

#include "s3.h"


ngx_uint_t
s3_metrics_method_slot(ngx_http_request_t *r)
{
    if (r->method == NGX_HTTP_GET) {
        return XROOTD_S3_METHOD_GET;
    }
    if (r->method == NGX_HTTP_HEAD) {
        return XROOTD_S3_METHOD_HEAD;
    }
    if (r->method == NGX_HTTP_PUT) {
        return XROOTD_S3_METHOD_PUT;
    }
    if (r->method == NGX_HTTP_DELETE) {
        return XROOTD_S3_METHOD_DELETE;
    }

    if (r->method == NGX_HTTP_POST) {
        return XROOTD_S3_METHOD_POST;
    }

    return XROOTD_S3_METHOD_OTHER;
}


static ngx_uint_t
s3_metrics_status_class(ngx_uint_t http_status)
{
    if (http_status >= 100 && http_status < 200) {
        return XROOTD_HTTP_STATUS_1XX;
    }
    if (http_status >= 200 && http_status < 300) {
        return XROOTD_HTTP_STATUS_2XX;
    }
    if (http_status >= 300 && http_status < 400) {
        return XROOTD_HTTP_STATUS_3XX;
    }
    if (http_status >= 400 && http_status < 500) {
        return XROOTD_HTTP_STATUS_4XX;
    }
    if (http_status >= 500 && http_status < 600) {
        return XROOTD_HTTP_STATUS_5XX;
    }

    return XROOTD_HTTP_STATUS_OTHER;
}


void
s3_metrics_request_method(ngx_uint_t method_slot)
{
    if (method_slot >= XROOTD_S3_NMETHODS) {
        method_slot = XROOTD_S3_METHOD_OTHER;
    }

    XROOTD_S3_METRIC_INC(requests_total[method_slot]);
}


void
s3_metrics_response_status(ngx_uint_t method_slot, ngx_uint_t http_status)
{
    ngx_uint_t status_class;

    if (method_slot >= XROOTD_S3_NMETHODS) {
        method_slot = XROOTD_S3_METHOD_OTHER;
    }

    status_class = s3_metrics_status_class(http_status);
    XROOTD_S3_METRIC_INC(responses_total[method_slot][status_class]);
}


void
s3_metrics_response_method(ngx_http_request_t *r, ngx_uint_t method_slot,
    ngx_int_t handler_rc)
{
    ngx_uint_t http_status;

    /*
     * NGX_DONE means nginx will finish the request asynchronously, e.g. after
     * reading a PUT body.  The callback accounts for the final response.
     */
    if (handler_rc == NGX_DONE) {
        return;
    }

    if (handler_rc == NGX_ERROR) {
        http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else if (handler_rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        http_status = (ngx_uint_t) handler_rc;
    } else if (r->headers_out.status != 0) {
        http_status = r->headers_out.status;
    } else {
        http_status = NGX_HTTP_OK;
    }

    s3_metrics_response_status(method_slot, http_status);
}


ngx_int_t
s3_metrics_return_method(ngx_http_request_t *r, ngx_uint_t method_slot,
    ngx_int_t handler_rc)
{
    s3_metrics_response_method(r, method_slot, handler_rc);
    return handler_rc;
}


void
s3_metrics_finalize_request_method(ngx_http_request_t *r,
    ngx_uint_t method_slot, ngx_int_t handler_rc)
{
    s3_metrics_response_method(r, method_slot, handler_rc);
    ngx_http_finalize_request(r, handler_rc);
}
