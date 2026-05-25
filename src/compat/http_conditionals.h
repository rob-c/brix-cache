#ifndef XROOTD_COMPAT_HTTP_CONDITIONALS_H
#define XROOTD_COMPAT_HTTP_CONDITIONALS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/stat.h>

/*
 * XROOTD_HTTP_COND_WEAK_EQUIV — flag enabling weak ETag equivalence (W/"etag" ≡ "etag").
 *
 * WHAT: Bit mask value 0x0001 passed to xrootd_http_etag_list_contains() and
 *      xrootd_http_check_etag_preconditions(). WHY: RFC 7232 §2.3 defines weak equivalence;
 *      callers use this flag when comparing If-None-Match headers against resource ETags. */

#define XROOTD_HTTP_COND_WEAK_EQUIV  0x0001

/*
 * xrootd_http_etag_list_contains - check whether an ETag header value matches a target ETag.
 *
 * WHAT: Scans the ETag header string for occurrences of the target etag value,
 *       respecting weak equivalence flags (XROOTD_HTTP_COND_WEAK_EQUIV).
 *
 * WHY: HTTP conditional requests (If-None-Match / If-Match) carry ETag lists.
 *      The server must check whether any entry in the list matches the resource
 *      ETag to decide between 304 Not Modified and full response.
 *
 * HOW: Strips weak-prefix markers from header entries when flags include WEAK_EQUIV,
 *      then compares each entry against the target etag string.
 */
ngx_int_t xrootd_http_etag_list_contains(const ngx_str_t *header,
    const char *etag, unsigned flags);

/*
 * xrootd_http_check_etag_preconditions - evaluate If-None-Match / If-Match against resource ETag.
 *
 * WHAT: Checks HTTP conditional request preconditions based on the resource's
 *       mtime/size-derived ETag. Returns NGX_OK if conditions pass, NGX_HTTP_NOT_MODIFIED
 *       (304) for If-None-Match match, or NGX_HTTP_PRECONDITION_FAILED (412) for
 *       If-Match mismatch.
 *
 * WHY: RFC 7232 §3 requires servers to validate ETag-based conditional requests before
 *      returning content. This function centralises the decision logic so WebDAV and S3
 *      agree on behaviour.
 *
 * HOW: Generates resource ETag from mtime/size via xrootd_http_etag_str(), then checks
 *      against the If-None-Match / If-Match header using xrootd_http_etag_list_contains().
 */
ngx_int_t xrootd_http_check_etag_preconditions(ngx_http_request_t *r,
    ngx_flag_t resource_exists, const struct stat *st, unsigned etag_flags,
    unsigned condition_flags);

/*
 * xrootd_http_check_if_modified_since - evaluate If-Modified-Since / If-Unmodified-Since.
 *
 * WHAT: Compares the resource's mtime against the HTTP date in If-Modified-Since
 *       or If-Unmodified-Since header. Returns NGX_OK if conditions pass,
 *       NGX_HTTP_NOT_MODIFIED (304) for If-Modified-Since match, or 412 for
 *       If-Unmodified-Since mismatch.
 *
 * WHY: RFC 7232 §3.3 requires servers to validate time-based conditional requests.
 *      This enables cache-friendly 304 responses for clients with stale ETags but
 *      current modification timestamps.
 *
 * HOW: Parses the HTTP date header, compares against st->st_mtime. If-Modified-Since
 *      returns 304 when mtime <= header date; If-Unmodified-Since returns 412 when
 *      mtime > header date.
 */
ngx_int_t xrootd_http_check_if_modified_since(ngx_http_request_t *r,
    time_t mtime);

/*
 * xrootd_http_overwrite_forbidden - check whether Over: false header forbids overwrite.
 *
 * WHAT: Returns NGX_TRUE if the HTTP Over header is "false" and the target resource
 *       already exists, indicating the client does not want to overwrite existing data.
 *
 * WHY: WebDAV RFC 4918 §9.9 defines the Over header to control overwrite behaviour on
 *      PUT/MOVE/COPY. Servers must respect Over: false by returning 412 Precondition Failed
 *      when the target exists.
 *
 * HOW: Looks up the Over header via xrootd_http_find_header(), checks value equals "false"
 *      (case-insensitive, trimmed), and verifies resource_exists flag.
 */
ngx_flag_t xrootd_http_overwrite_forbidden(ngx_http_request_t *r);

#endif /* XROOTD_COMPAT_HTTP_CONDITIONALS_H */
