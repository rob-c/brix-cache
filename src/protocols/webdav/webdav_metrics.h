/*
 * webdav/webdav_metrics.h
 *
 * WebDAV per-request metric helpers: classify the method slot, count arrivals,
 * record response outcomes, and the status-only / finalise convenience tails.
 * Split out of webdav.h so the metrics surface is grouped by concern and
 * individually reviewable.  Includes webdav.h for the shared request types.
 */

#ifndef NGX_HTTP_BRIX_WEBDAV_METRICS_H
#define NGX_HTTP_BRIX_WEBDAV_METRICS_H

#include "webdav.h"

/* Classify the request method into the WebDAV metric slot (the requests_total
 * index); BRIX_WEBDAV_METHOD_OTHER for unrecognised verbs. */
ngx_uint_t webdav_metrics_method(ngx_http_request_t *r);
/* Count this request's arrival (requests_total[method]). */
void webdav_metrics_request(ngx_http_request_t *r);
/* Record the outcome (responses_total[method][status-class] + unified op),
 * deriving the status from rc/headers_out.  No-op when rc == NGX_DONE (the
 * request already accounted for itself). */
void webdav_metrics_response(ngx_http_request_t *r, ngx_int_t rc);
/* webdav_metrics_response(r, rc) then return rc — convenience for handler tails. */
ngx_int_t webdav_metrics_return(ngx_http_request_t *r, ngx_int_t rc);
/* Session lifecycle hooks paired with the metrics finalization point. */
void webdav_sess_begin_request(ngx_http_request_t *r);
void webdav_sess_attempt_request(ngx_http_request_t *r);
/* Emit a status-only (empty-body) response — set status + zero content length,
 * send the header, and finalise via the send_special result (records response
 * metrics).  Finalises the request: must be the caller's last action on `r`.
 * Set any extra headers (e.g. Location for 201) before calling. */
void webdav_send_status_only(ngx_http_request_t *r, ngx_uint_t status);
/* webdav_metrics_response(r, rc) then ngx_http_finalize_request(r, rc) — for
 * async/self-finalising paths. */
void webdav_metrics_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

#endif /* NGX_HTTP_BRIX_WEBDAV_METRICS_H */
