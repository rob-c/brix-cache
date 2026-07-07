/*
 * metrics.c - WebDAV request/result accounting helpers.
 */

#include "webdav.h"
#include "core/http/http_headers.h"
#include "core/http/sesslog_conn.h"
#include "observability/metrics/http_common.h"
#include "observability/metrics/unified.h"

static brix_metric_op_t
webdav_unified_op(ngx_uint_t method)
{
    switch (method) {
    case BRIX_WEBDAV_METHOD_GET:
        return BRIX_METRIC_OP_READ;
    case BRIX_WEBDAV_METHOD_HEAD:
        return BRIX_METRIC_OP_STAT;
    case BRIX_WEBDAV_METHOD_PUT:
        return BRIX_METRIC_OP_WRITE;
    case BRIX_WEBDAV_METHOD_DELETE:
        return BRIX_METRIC_OP_DELETE;
    case BRIX_WEBDAV_METHOD_MKCOL:
        return BRIX_METRIC_OP_MKDIR;
    case BRIX_WEBDAV_METHOD_COPY:
        return BRIX_METRIC_OP_TPC;
    case BRIX_WEBDAV_METHOD_PROPFIND:
        return BRIX_METRIC_OP_DIRLIST;
    default:
        return BRIX_METRIC_OP_STAT;
    }
}

static brix_sess_mode_t
webdav_sess_mode(ngx_http_request_t *r, ngx_uint_t method)
{
    if (method == BRIX_WEBDAV_METHOD_GET) {
        return BRIX_SESS_MODE_READ;
    }
    if (method == BRIX_WEBDAV_METHOD_PUT
        || method == BRIX_WEBDAV_METHOD_MKCOL
        || (r != NULL && r->method == NGX_HTTP_MOVE))
    {
        return BRIX_SESS_MODE_WRITE;
    }
    if (method == BRIX_WEBDAV_METHOD_DELETE) {
        return BRIX_SESS_MODE_DELETE;
    }
    if (method == BRIX_WEBDAV_METHOD_COPY) {
        return BRIX_SESS_MODE_COPY;
    }
    if (method == BRIX_WEBDAV_METHOD_PROPFIND) {
        ngx_str_t depth = brix_http_get_header(r, "Depth");
        if (depth.len == 1 && depth.data[0] == '0') {
            return BRIX_SESS_MODE_META;
        }
        return BRIX_SESS_MODE_LIST;
    }

    return BRIX_SESS_MODE_META;
}

static brix_sess_am_t
webdav_sess_auth_method(ngx_http_brix_webdav_req_ctx_t *ctx)
{
    if (ctx == NULL) {
        return BRIX_SESS_AM_ANON;
    }

    if (ctx->token_auth) {
        return BRIX_SESS_AM_TOKEN;
    }

    if (ctx->verified) {
        return BRIX_SESS_AM_GSI;
    }

    return BRIX_SESS_AM_ANON;
}

static const char *
webdav_sess_user(ngx_http_brix_webdav_req_ctx_t *ctx)
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

static const char *
webdav_sess_vo(ngx_http_brix_webdav_req_ctx_t *ctx)
{
    const char *vo;

    if (ctx == NULL || ctx->identity == NULL) {
        return "-";
    }

    vo = brix_identity_vo_csv_cstr(ctx->identity);
    return vo != NULL && vo[0] != '\0' ? vo : "-";
}

static brix_sess_t *
webdav_sess(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_http_brix_webdav_req_ctx_t  *ctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    return brix_http_sess(r, &conf->common, BRIX_SESS_PROTO_WEBDAV,
                          webdav_sess_auth_method(ctx));
}

static int
webdav_sess_mode_has_xfer(brix_sess_mode_t mode)
{
    return mode == BRIX_SESS_MODE_READ || mode == BRIX_SESS_MODE_WRITE
           || mode == BRIX_SESS_MODE_COPY;
}

static int64_t
webdav_sess_xfer_expected(ngx_http_request_t *r, brix_sess_mode_t mode)
{
    if (r == NULL) {
        return -1;
    }

    if (mode == BRIX_SESS_MODE_READ || mode == BRIX_SESS_MODE_COPY) {
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
webdav_sess_xfer_bytes(ngx_http_request_t *r, brix_sess_mode_t mode,
    int64_t expected)
{
    if (mode == BRIX_SESS_MODE_READ || mode == BRIX_SESS_MODE_COPY) {
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
webdav_sess_start_xfer(ngx_http_request_t *r, brix_sess_t *sess,
    const char *path, brix_sess_mode_t mode)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;

    if (!webdav_sess_mode_has_xfer(mode)) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL || ctx->sess_xfer_started) {
        return;
    }

    brix_sess_xfer_start(sess, &ctx->sess_xfer, path, mode, -1);
    ctx->sess_xfer_started = ctx->sess_xfer.active ? 1 : 0;
}

static void
webdav_sess_finish_xfer(ngx_http_request_t *r, brix_sess_t *sess,
    brix_sess_mode_t mode, ngx_uint_t status)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;
    int64_t                         expected;
    uint64_t                        bytes;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL || !ctx->sess_xfer_started) {
        return;
    }

    if (mode == BRIX_SESS_MODE_COPY && ctx->sess_xfer.expected >= 0) {
        expected = ctx->sess_xfer.expected;
        bytes = ctx->sess_xfer.bytes;
    } else {
        expected = webdav_sess_xfer_expected(r, mode);
        bytes = webdav_sess_xfer_bytes(r, mode, expected);
    }
    ctx->sess_xfer.expected = expected;
    if (bytes > ctx->sess_xfer.bytes) {
        brix_sess_xfer_add(&ctx->sess_xfer, bytes - ctx->sess_xfer.bytes);
    }

    brix_sess_xfer_end(sess, &ctx->sess_xfer,
                       status < NGX_HTTP_BAD_REQUEST
                       ? BRIX_SESS_XFER_COMPLETE
                       : BRIX_SESS_XFER_ABORTED);
    ctx->sess_xfer_started = 0;
}

void
webdav_sess_begin_request(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;
    brix_sess_t                    *sess;
    brix_sess_am_t                  method;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    method = webdav_sess_auth_method(ctx);
    sess = webdav_sess(r);
    brix_sess_auth_once(sess, method, webdav_sess_user(ctx),
                        webdav_sess_vo(ctx));
}

void
webdav_sess_attempt_request(ngx_http_request_t *r)
{
    char         path[BRIX_SESSLOG_PATH_MAX];
    ngx_uint_t   method;
    brix_sess_t *sess;
    brix_sess_mode_t mode;

    method = webdav_metrics_method(r);
    sess = webdav_sess(r);
    mode = webdav_sess_mode(r, method);
    brix_sess_attempt(sess, brix_http_sess_uri(r, path, sizeof(path)), mode);
    webdav_sess_start_xfer(r, sess, path, mode);
}

/**
 * WHAT: Map nginx HTTP method to the WebDAV metric enum for Prometheus request counting.
 *
 * Returns a value from BRIX_WEBDAV_METHOD_* enum corresponding to the incoming
 * request's HTTP method. Uses r->method (nginx internal enum) for OPTIONS/HEAD/GET/
 * PUT/DELETE; uses r->method_name string comparison for WebDAV-specific methods
 * MKCOL, COPY, and PROPFIND (which nginx doesn't have built-in enums for). Returns
 * BRIX_WEBDAV_METHOD_OTHER as fallback for unknown or custom methods. All callers
 * use this to index into the requests_total[METHOD] metric counter before processing
 * begins or after completing an operation.
 */
ngx_uint_t
webdav_metrics_method(ngx_http_request_t *r)
{
    const brix_http_operation_t *op;

    op = brix_http_operation_find(r, brix_webdav_operations,
                                    brix_webdav_operations_count);

    return op ? op->metric_slot : BRIX_WEBDAV_METHOD_OTHER;
}

/**
 * WHAT: Increment the WebDAV requests_total counter for this request's method.
 *
 * Called early in each handler to record that a request arrived for a specific HTTP
 * method. Uses webdav_metrics_method() to classify the method, then increments the
 * requests_total[method] Prometheus metric via BRIX_WEBDAV_METRIC_INC(). This is
 * typically called at the start of every WebDAV operation handler (GET, PUT, DELETE, etc.)
 * before any processing begins. Does not track status — only counts request arrivals.
 */
void
webdav_metrics_request(ngx_http_request_t *r)
{
    ngx_uint_t method = webdav_metrics_method(r);

    BRIX_WEBDAV_METRIC_INC(requests_total[method]);
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
    brix_sess_t *sess;
    char path[BRIX_SESSLOG_PATH_MAX];
    char errscratch[BRIX_SESSLOG_ERR_MAX];

    if (rc == NGX_DONE) {
        return;
    }

    method = webdav_metrics_method(r);

    status = brix_http_effective_status(r, rc);
    status_class = brix_http_status_class(status);
    sess = webdav_sess(r);
    brix_sess_result(sess, status < NGX_HTTP_BAD_REQUEST,
                     brix_http_sess_uri(r, path, sizeof(path)),
                     webdav_sess_mode(r, method),
                     status < NGX_HTTP_BAD_REQUEST ? NULL
                         : brix_sesslog_err_from_http((int) status,
                                                       errscratch,
                                                       sizeof(errscratch)));
    webdav_sess_finish_xfer(r, sess, webdav_sess_mode(r, method), status);
    BRIX_WEBDAV_METRIC_INC(responses_total[method][status_class]);
    brix_metric_op_done(BRIX_PROTO_WEBDAV, webdav_unified_op(method),
                          0, 0,
                          brix_metric_err_from_http_status(status));
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

/**
 * WHAT: Emit a status-only (empty-body) response and finalize the request.
 *
 * Captures the recurring four-line tail used by status-only outcomes
 * (201/204/… with no body): set the status and a zero content length, send the
 * header, then finalize via the send_special result so response metrics are
 * recorded.  Equivalent to:
 *   r->headers_out.status = status;
 *   r->headers_out.content_length_n = 0;
 *   ngx_http_send_header(r);
 *   webdav_metrics_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_LAST));
 *
 * The caller still owns flow control: this finalizes the request, so it must be
 * the last action on `r` and the caller should return immediately after.  Add
 * any response headers (e.g. Location for 201) before calling.
 */
void
webdav_send_status_only(ngx_http_request_t *r, ngx_uint_t status)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    webdav_metrics_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_LAST));
}
