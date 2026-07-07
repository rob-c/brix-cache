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
#include "core/http/sesslog_conn.h"
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

static brix_sess_mode_t
s3_sess_mode(ngx_uint_t method_slot)
{
    switch (method_slot) {
    case BRIX_S3_METHOD_GET:
        return BRIX_SESS_MODE_READ;
    case BRIX_S3_METHOD_PUT:
    case BRIX_S3_METHOD_POST:
        return BRIX_SESS_MODE_WRITE;
    case BRIX_S3_METHOD_DELETE:
        return BRIX_SESS_MODE_DELETE;
    case BRIX_S3_METHOD_LIST:
        return BRIX_SESS_MODE_LIST;
    case BRIX_S3_METHOD_HEAD:
    default:
        return BRIX_SESS_MODE_META;
    }
}

static brix_sess_am_t
s3_sess_auth_method(const ngx_http_s3_req_ctx_t *ctx)
{
    if (ctx == NULL || ctx->identity == NULL) {
        return BRIX_SESS_AM_ANON;
    }

    if (ctx->identity->auth_method & BRIX_AUTHN_TOKEN) {
        return BRIX_SESS_AM_TOKEN;
    }

    if (ctx->identity->auth_method & BRIX_AUTHN_S3KEY) {
        return BRIX_SESS_AM_SIGV4;
    }

    return BRIX_SESS_AM_ANON;
}

static const char *
s3_sess_user(const ngx_http_s3_req_ctx_t *ctx)
{
    const char *subject;

    if (ctx == NULL || ctx->identity == NULL) {
        return "-";
    }

    subject = brix_identity_subject_cstr(ctx->identity);
    if (subject != NULL && subject[0] != '\0') {
        return subject;
    }

    subject = brix_identity_dn_cstr(ctx->identity);
    return subject != NULL && subject[0] != '\0' ? subject : "-";
}

static brix_sess_t *
s3_sess(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t *cf;
    ngx_http_s3_req_ctx_t  *ctx;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);

    return brix_http_sess(r, &cf->common, BRIX_SESS_PROTO_S3,
                          s3_sess_auth_method(ctx));
}

static int
s3_sess_method_has_xfer(ngx_uint_t method_slot)
{
    return method_slot == BRIX_S3_METHOD_GET
           || method_slot == BRIX_S3_METHOD_PUT;
}

static int64_t
s3_sess_xfer_expected(ngx_http_request_t *r, brix_sess_mode_t mode)
{
    if (r == NULL) {
        return -1;
    }

    if (mode == BRIX_SESS_MODE_READ) {
        return r->headers_out.content_length_n >= 0
               ? (int64_t) r->headers_out.content_length_n : -1;
    }

    if (mode == BRIX_SESS_MODE_WRITE) {
        return r->headers_in.content_length_n >= 0
               ? (int64_t) r->headers_in.content_length_n : -1;
    }

    return -1;
}

static uint64_t
s3_sess_xfer_bytes(ngx_http_request_t *r, brix_sess_mode_t mode,
    int64_t expected)
{
    if (mode == BRIX_SESS_MODE_READ) {
        return expected > 0 ? (uint64_t) expected : 0;
    }

    if (mode == BRIX_SESS_MODE_WRITE && r != NULL
        && r->headers_in.content_length_n > 0)
    {
        return (uint64_t) r->headers_in.content_length_n;
    }

    return 0;
}

static void
s3_sess_start_xfer(ngx_http_request_t *r, brix_sess_t *sess,
    const char *path, ngx_uint_t method_slot)
{
    ngx_http_s3_req_ctx_t *ctx;

    if (!s3_sess_method_has_xfer(method_slot)) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    if (ctx == NULL || ctx->sess_xfer_started) {
        return;
    }

    brix_sess_xfer_start(sess, &ctx->sess_xfer, path,
                         s3_sess_mode(method_slot), -1);
    ctx->sess_xfer_started = ctx->sess_xfer.active ? 1 : 0;
}

static void
s3_sess_finish_xfer(ngx_http_request_t *r, brix_sess_t *sess,
    ngx_uint_t method_slot, ngx_uint_t http_status)
{
    ngx_http_s3_req_ctx_t *ctx;
    brix_sess_mode_t      mode;
    int64_t               expected;
    uint64_t              bytes;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    if (ctx == NULL || !ctx->sess_xfer_started) {
        return;
    }

    mode = s3_sess_mode(method_slot);
    expected = s3_sess_xfer_expected(r, mode);
    bytes = s3_sess_xfer_bytes(r, mode, expected);
    ctx->sess_xfer.expected = expected;
    if (bytes > ctx->sess_xfer.bytes) {
        brix_sess_xfer_add(&ctx->sess_xfer, bytes - ctx->sess_xfer.bytes);
    }

    brix_sess_xfer_end(sess, &ctx->sess_xfer,
                       http_status < NGX_HTTP_BAD_REQUEST
                       ? BRIX_SESS_XFER_COMPLETE
                       : BRIX_SESS_XFER_ABORTED);
    ctx->sess_xfer_started = 0;
}

void
s3_sess_begin_request(ngx_http_request_t *r, ngx_uint_t method_slot)
{
    ngx_http_s3_req_ctx_t *ctx;
    brix_sess_t          *sess;
    brix_sess_am_t        method;

    (void) method_slot;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    method = s3_sess_auth_method(ctx);
    sess = s3_sess(r);
    brix_sess_auth_once(sess, method, s3_sess_user(ctx), "-");
}

void
s3_sess_attempt_request(ngx_http_request_t *r, ngx_uint_t method_slot)
{
    char         path[BRIX_SESSLOG_PATH_MAX];
    brix_sess_t *sess;

    sess = s3_sess(r);
    brix_sess_attempt(sess, brix_http_sess_uri(r, path, sizeof(path)),
                      s3_sess_mode(method_slot));
    s3_sess_start_xfer(r, sess, path, method_slot);
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
    brix_sess_t *sess;
    char path[BRIX_SESSLOG_PATH_MAX];
    char errscratch[BRIX_SESSLOG_ERR_MAX];

    /*
     * NGX_DONE means nginx will finish the request asynchronously, e.g. after
     * reading a PUT body.  The callback accounts for the final response.
     */
    if (handler_rc == NGX_DONE) {
        return;
    }

    http_status = brix_http_effective_status(r, handler_rc);
    sess = s3_sess(r);
    brix_sess_result(sess, http_status < NGX_HTTP_BAD_REQUEST,
                     brix_http_sess_uri(r, path, sizeof(path)),
                     s3_sess_mode(method_slot),
                     http_status < NGX_HTTP_BAD_REQUEST ? NULL
                         : brix_sesslog_err_from_http((int) http_status,
                                                       errscratch,
                                                       sizeof(errscratch)));
    s3_sess_finish_xfer(r, sess, method_slot, http_status);
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
