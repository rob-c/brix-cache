/*
 * metrics.c - S3-compatible endpoint request/result accounting helpers.
 *
 * WHAT: Maps HTTP method codes to XRootD metric slot enums, increments request
 *       and response counters by method+status-class buckets, and converts handler
 *       return codes to HTTP status for metric recording. Provides six public functions:
 *       s3_metrics_method_slot (HTTP→metric enum), s3_metrics_request_method (request counter),
 *       s3_metrics_response_status (response counter by class), s3_metrics_response_method
 *       (handler RC → status → response counter), s3_metrics_return_method (counter + return),
 *       and s3_metrics_finalize_request_method (counter + ngx_http_finalize_request).
 *
 * WHY: S3-compatible endpoints require separate metric buckets from WebDAV/XRootD stream.
 *      Metrics track requests_total per-method and responses_total per-method×status-class.
 *      These helpers centralize method-to-slot mapping, status-class extraction via
 *      brix_http_status_class(), and handler-RC-to-HTTP-status conversion — ensuring all
 *      S3 handlers (get.c, put.c, list.c, multipart.c) use consistent metric accounting.
 *      NGX_DONE handling: async PUT body reads defer final response counting to callbacks.
 *
 * HOW: s3_metrics_method_slot() maps r->method enum values to BRIX_S3_METHOD_* constants —
 *      GET→GET, HEAD→HEAD, PUT→PUT, DELETE→DELETE, POST→POST, everything else→OTHER.
 *      s3_metrics_request_method() clamps method_slot to BRIX_S3_NMETHODS, increments
 *      requests_total[slot] via BRIX_S3_METRIC_INC(). s3_metrics_response_status() same clamp,
 *      extracts status_class from http_status via brix_http_status_class(), increments
 *      responses_total[slot][status_class]. s3_metrics_response_method() skips NGX_DONE (deferred),
 *      converts handler RC to HTTP status: ERROR→500, >=NGX_HTTP_SPECIAL_RESPONSE→RC value,
 *      r->headers_out.status non-zero→that value, else→200. Calls s3_metrics_response_status().
 *      s3_metrics_return_method() delegates response counting then returns original handler_rc.
 *      s3_metrics_finalize_request_method() same + calls ngx_http_finalize_request(r, handler_rc).
 */

#include "s3.h"
#include "core/http/http_headers.h"
#include "observability/metrics/http_common.h"
#include "observability/metrics/unified.h"

static brix_metric_op_t
s3_unified_op(ngx_uint_t method_slot)
{
    switch (method_slot) {
    case BRIX_S3_METHOD_GET:
        return BRIX_METRIC_OP_READ;
    case BRIX_S3_METHOD_HEAD:
        return BRIX_METRIC_OP_STAT;
    case BRIX_S3_METHOD_PUT:
    case BRIX_S3_METHOD_POST:
        return BRIX_METRIC_OP_WRITE;
    case BRIX_S3_METHOD_DELETE:
        return BRIX_METRIC_OP_DELETE;
    case BRIX_S3_METHOD_LIST:
        return BRIX_METRIC_OP_DIRLIST;
    default:
        return BRIX_METRIC_OP_STAT;
    }
}

ngx_uint_t
s3_metrics_method_slot(ngx_http_request_t *r)
{
    const brix_http_operation_t *op;

    op = brix_http_operation_find(r, brix_s3_operations,
                                    brix_s3_operations_count);

    return op ? op->metric_slot : BRIX_S3_METHOD_OTHER;
}

void
s3_metrics_request_method(ngx_uint_t method_slot)
{
    if (method_slot >= BRIX_S3_NMETHODS) {
        method_slot = BRIX_S3_METHOD_OTHER;
    }

    BRIX_S3_METRIC_INC(requests_total[method_slot]);
}

void
s3_metrics_response_status(ngx_uint_t method_slot, ngx_uint_t http_status)
{
    ngx_uint_t status_class;

    if (method_slot >= BRIX_S3_NMETHODS) {
        method_slot = BRIX_S3_METHOD_OTHER;
    }

    status_class = brix_http_status_class(http_status);
    BRIX_S3_METRIC_INC(responses_total[method_slot][status_class]);
    brix_metric_op_done(BRIX_PROTO_S3, s3_unified_op(method_slot),
                          0, 0,
                          brix_metric_err_from_http_status(http_status));
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

    http_status = brix_http_effective_status(r, handler_rc);
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
