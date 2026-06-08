/*
 * metrics.c - WebDAV request/result accounting helpers.
 */

#include "webdav.h"
#include "../compat/http_headers.h"
#include "../metrics/http_common.h"
#include "../metrics/unified.h"

static xrootd_metric_op_t
webdav_unified_op(ngx_uint_t method)
{
    switch (method) {
    case XROOTD_WEBDAV_METHOD_GET:
        return XROOTD_METRIC_OP_READ;
    case XROOTD_WEBDAV_METHOD_HEAD:
        return XROOTD_METRIC_OP_STAT;
    case XROOTD_WEBDAV_METHOD_PUT:
        return XROOTD_METRIC_OP_WRITE;
    case XROOTD_WEBDAV_METHOD_DELETE:
        return XROOTD_METRIC_OP_DELETE;
    case XROOTD_WEBDAV_METHOD_MKCOL:
        return XROOTD_METRIC_OP_MKDIR;
    case XROOTD_WEBDAV_METHOD_COPY:
        return XROOTD_METRIC_OP_TPC;
    case XROOTD_WEBDAV_METHOD_PROPFIND:
        return XROOTD_METRIC_OP_DIRLIST;
    default:
        return XROOTD_METRIC_OP_STAT;
    }
}

/**
 * WHAT: Map nginx HTTP method to the WebDAV metric enum for Prometheus request counting.
 *
 * Returns a value from XROOTD_WEBDAV_METHOD_* enum corresponding to the incoming
 * request's HTTP method. Uses r->method (nginx internal enum) for OPTIONS/HEAD/GET/
 * PUT/DELETE; uses r->method_name string comparison for WebDAV-specific methods
 * MKCOL, COPY, and PROPFIND (which nginx doesn't have built-in enums for). Returns
 * XROOTD_WEBDAV_METHOD_OTHER as fallback for unknown or custom methods. All callers
 * use this to index into the requests_total[METHOD] metric counter before processing
 * begins or after completing an operation.
 */
ngx_uint_t
webdav_metrics_method(ngx_http_request_t *r)
{
    const xrootd_http_operation_t *op;

    op = xrootd_http_operation_find(r, xrootd_webdav_operations,
                                    xrootd_webdav_operations_count);

    return op ? op->metric_slot : XROOTD_WEBDAV_METHOD_OTHER;
}

/**
 * WHAT: Increment the WebDAV requests_total counter for this request's method.
 *
 * Called early in each handler to record that a request arrived for a specific HTTP
 * method. Uses webdav_metrics_method() to classify the method, then increments the
 * requests_total[method] Prometheus metric via XROOTD_WEBDAV_METRIC_INC(). This is
 * typically called at the start of every WebDAV operation handler (GET, PUT, DELETE, etc.)
 * before any processing begins. Does not track status — only counts request arrivals.
 */
void
webdav_metrics_request(ngx_http_request_t *r)
{
    ngx_uint_t method = webdav_metrics_method(r);

    XROOTD_WEBDAV_METRIC_INC(requests_total[method]);
}

/**
 * WHAT: Increment the WebDAV responses_total counter by method and status class.
 *
 * Called at end of each handler to record the outcome of processing. Determines the HTTP
 * status from either rc (error code), r->headers_out.status (explicitly set response), or
 * defaults to NGX_HTTP_OK if no status was set. Maps to a low-cardinality status class via
 * webdav_metrics_status_class(), then increments responses_total[method][status_class].
 * Returns immediately if rc == NGX_DONE (request already finalized, metrics should not be
 * double-counted). Used by all handlers after completing their operation logic.
 */
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

    status = xrootd_http_effective_status(r, rc);
    status_class = xrootd_http_status_class(status);
    XROOTD_WEBDAV_METRIC_INC(responses_total[method][status_class]);
    xrootd_metric_op_done(XROOTD_PROTO_WEBDAV, webdav_unified_op(method),
                          0, 0,
                          xrootd_metric_err_from_http_status(status));
}

/**
 * WHAT: Wrapper helper — records response metrics then returns the original rc value.
 *
 * Convenience function that calls webdav_metrics_response(r, rc) and immediately returns
 * rc to the caller. Used by handlers that want to record metrics before returning an nginx
 * result code without needing two separate statement lines. Equivalent to:
 *   webdav_metrics_response(r, rc); return rc;
 */
ngx_int_t
webdav_metrics_return(ngx_http_request_t *r, ngx_int_t rc)
{
    webdav_metrics_response(r, rc);
    return rc;
}

/**
 * WHAT: Wrapper helper — records response metrics then finalizes the nginx request.
 *
 * Convenience function that calls webdav_metrics_response(r, rc) followed by
 * ngx_http_finalize_request(r, rc). Used by handlers that want to record metrics and
 * complete the request lifecycle in a single call. Equivalent to:
 *   webdav_metrics_response(r, rc); ngx_http_finalize_request(r, rc);
 */
void
webdav_metrics_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    webdav_metrics_response(r, rc);
    ngx_http_finalize_request(r, rc);
}
