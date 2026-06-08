/*
 * src/webdav/response_helpers.h - WebDAV HTTP response helper functions.
 *
 * WHAT: Provides inline helper functions for common WebDAV response patterns.
 *       Consolidates boilerplate code for sending status, headers, and body.
 *
 * WHY: WebDAV handlers repeatedly follow the same response pattern:
 *      1. Set response status
 *      2. Set content_length_n (usually 0 for no-content responses)
 *      3. Send headers via ngx_http_send_header()
 *      4. Send body (or empty response) via ngx_http_send_special()
 *      This pattern repeats 17+ times across propfind.c, put.c, get.c, etc.
 *
 * HOW: Inline functions encapsulate the pattern. All functions are static
 *      inline for zero function call overhead. Use in place of manual
 *      response building code.
 */

#ifndef XROOTD_WEBDAV_RESPONSE_HELPERS_H
#define XROOTD_WEBDAV_RESPONSE_HELPERS_H

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* ---- webdav_send_empty_response(r, status) ----
 *
 * Send an HTTP response with the given status code and no body (Content-Length: 0).
 * Used for responses like 204 No Content, 201 Created (when no body needed), etc.
 *
 * USAGE:
 *   return webdav_send_empty_response(r, NGX_HTTP_NO_CONTENT);
 */
static inline ngx_int_t
webdav_send_empty_response(ngx_http_request_t *r, ngx_uint_t status)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/* ---- webdav_send_status_with_content_length(r, status, len) ----
 *
 * Send an HTTP response with the given status code and Content-Length header.
 * Used when the response body size is known (e.g., GET response).
 * Caller is responsible for actually sending the body via ngx_http_output_filter().
 *
 * RETURNS: NGX_OK if headers sent successfully, NGX_ERROR on failure.
 *
 * USAGE:
 *   rc = webdav_send_status_with_content_length(r, NGX_HTTP_OK, file_size);
 *   if (rc != NGX_OK) { return rc; }
 *   // Now send body
 */
static inline ngx_int_t
webdav_send_status_with_content_length(ngx_http_request_t *r,
                                       ngx_uint_t status,
                                       off_t content_length)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = content_length;
    return ngx_http_send_header(r);
}

/* ---- webdav_send_status_no_header(r, status) ----
 *
 * Set response status and content_length_n = 0 without sending headers.
 * Used when additional header manipulation is needed before sending.
 *
 * USAGE:
 *   webdav_send_status_no_header(r, NGX_HTTP_OK);
 *   // Add custom headers here
 *   h = ngx_list_push(&r->headers_out.headers);
 *   ...
 *   ngx_http_send_header(r);
 */
static inline void
webdav_send_status_no_header(ngx_http_request_t *r, ngx_uint_t status)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
}

/* ---- webdav_send_only_status(r, status) ----
 *
 * Send only the status header with no body (typically for error responses).
 * Shorthand for setting status and sending headers immediately.
 *
 * USAGE:
 *   return webdav_send_only_status(r, NGX_HTTP_NOT_FOUND);
 */
static inline ngx_int_t
webdav_send_only_status(ngx_http_request_t *r, ngx_uint_t status)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
}

#endif /* XROOTD_WEBDAV_RESPONSE_HELPERS_H */
