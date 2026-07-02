#ifndef XROOTD_COMPAT_HTTP_FILE_RESPONSE_H
#define XROOTD_COMPAT_HTTP_FILE_RESPONSE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/types.h>
#include <time.h>

#include "http_headers.h"

/*
 * xrootd_http_set_header - set an HTTP response header with a string value.
 *
 * WHAT: Pushes a new header entry onto r->headers_out.headers with key and string
 *       value. Optionally returns the ngx_table_elt_t pointer via out.
 *
 * WHY: WebDAV and S3 responses need to set various headers (ETag, Content-Range,
 *      Accept-Ranges, etc.) in a uniform way. This function handles nginx header list
 *      insertion with pool allocation.
 *
 * HOW: Wraps xrootd_http_set_header_str() — pushes onto r->headers_out.headers via
 *      ngx_list_push(), sets key/hash/value, copies value into pool if copy_value=1.
 */
ngx_int_t xrootd_http_set_header(ngx_http_request_t *r, const char *key,
    const char *value, ngx_table_elt_t **out);

/*
 * xrootd_http_add_etag_header - generate and set an ETag header from resource metadata.
 *
 * WHAT: Computes an ETag string from mtime/size via xrootd_http_etag_str(), then sets
 *       it as the ETag response header. Optionally registers h as r->headers_out.etag
 *       for later conditional-request comparison.
 *
 * WHY: RFC 7232 §2.3 requires servers to emit ETags on responses with payload. WebDAV
 *      PROPFIND and S3 HEAD/GET both need ETag headers. Registering r->headers_out.etag
 *      enables downstream conditional-request checks (If-None-Match).
 *
 * HOW: Calls xrootd_http_etag_str() to format ETag, then xrootd_http_set_header() to
 *      insert it into headers_out. Sets r->headers_out.etag = h when register_not_modified.
 */
ngx_int_t xrootd_http_add_etag_header(ngx_http_request_t *r, time_t mtime,
    off_t size, unsigned etag_flags, ngx_flag_t register_not_modified);

/*
 * xrootd_http_add_content_range_header - set Content-Range header for partial responses.
 *
 * WHAT: Formats "bytes start-end/size" into the Content-Range response header.
 *
 * WHY: HTTP Range requests (RFC 7233 §4.2) require servers to return 206 Partial
 *      Content with a Content-Range header specifying the served byte range and
 *      total resource size.
 *
 * HOW: snprintf("bytes %lld-%lld/%lld") into temporary buffer, then xrootd_http_set_header()
 *      to insert it into headers_out.
 */
ngx_int_t xrootd_http_add_content_range_header(ngx_http_request_t *r,
    off_t start, off_t end, off_t size);

/*
 * xrootd_http_send_file_range - build and send a file-backed response for a byte range.
 *
 * WHAT: Creates a file-backed ngx_buf_t covering [start, start+len], optionally adds
 *       pool cleanup to close the fd after the response is sent, then sends headers
 *       and filters the chain through nginx output.
 *
 * WHY: WebDAV GET with Range header and S3 GET need to serve file content via nginx's
 *      sendfile path (zero-copy from disk). This function handles buffer setup, cleanup,
 *      and response dispatch in one call.
 *
 * HOW: Allocates ngx_buf_t + ngx_file_t from r->pool. Sets file/pos/last for the range.
 *      If close_fd=1, adds ngx_pool_cleanup_file() to auto-close fd post-response.
 *      Sends header via ngx_http_send_header(), then ngx_http_output_filter(r, &out).
 */
ngx_int_t xrootd_http_send_file_range(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path, off_t start, off_t len, ngx_flag_t close_fd);

/*
 * xrootd_http_chain_append_file_range - append a file-backed chain link for [start, end].
 *
 * WHAT: Allocates ngx_buf_t + ngx_file_t from r->pool for the byte range [start, end]
 *       (inclusive), links it onto the chain via *tail, and optionally registers a pool
 *       cleanup to close fd after the response is flushed.
 *
 * WHY: Both xrdhttp_multipart.c and any future multi-range handler need to build a chain
 *      of individual file-range links.  Centralising the alloc + cleanup registration
 *      removes the duplicated open-coded pattern.
 *
 * HOW: Allocates buf + file from r->pool; sets in_file, file_pos, file_last; if close_fd=1
 *      registers ngx_pool_cleanup_file to auto-close fd; appends link to *tail.
 *      Returns NGX_OK on success, NGX_ERROR on OOM.
 *
 * Parameters:
 *   tail     — pointer to the chain's current tail link (updated to new link on success).
 *   start    — inclusive start offset.
 *   end      — inclusive end offset (file_last = end + 1).
 *   close_fd — 1: register pool cleanup to close fd; 0: caller owns fd lifetime.
 */
ngx_int_t xrootd_http_chain_append_file_range(ngx_http_request_t *r,
    ngx_chain_t **tail, ngx_fd_t fd, const char *path,
    off_t start, off_t end, ngx_flag_t close_fd);

/*
 * xrootd_http_set_file_headers - set the standard file-serving response headers.
 *
 * WHAT: Sets status (200 or 206), content_length_n, last_modified_time, Content-Type,
 *       ETag, and (if has_range) Content-Range on r->headers_out in one call.
 *
 * WHY: S3 GET, S3 HEAD, and WebDAV GET all populate the same set of response
 *      headers from a stat result. Centralising this removes the duplicated
 *      5-header block across the three handlers.
 *
 * Parameters:
 *   total_size   — st_size from fstat; used for ETag and Content-Range/total.
 *   send_len     — bytes to send (< total_size when has_range; == total_size for HEAD).
 *   content_type — literal/pool-allocated string, or NULL to use nginx types{} lookup.
 *   etag_flags   — 0 for strong (S3) or XROOTD_ETAG_WEAK for weak (WebDAV).
 *   has_range    — 1 if serving a byte range; 0 for full-object responses.
 *   range_start/range_end — inclusive byte offsets (ignored when has_range == 0).
 */
ngx_int_t xrootd_http_set_file_headers(ngx_http_request_t *r,
    time_t mtime, off_t total_size, off_t send_len,
    const char *content_type, unsigned etag_flags,
    int has_range, off_t range_start, off_t range_end);

#endif /* XROOTD_COMPAT_HTTP_FILE_RESPONSE_H */
