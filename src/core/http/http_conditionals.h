#ifndef BRIX_COMPAT_HTTP_CONDITIONALS_H
#define BRIX_COMPAT_HTTP_CONDITIONALS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/stat.h>

/*
 * BRIX_HTTP_COND_WEAK_EQUIV — flag enabling weak ETag equivalence (W/"etag" ≡ "etag").
 *
 * WHAT: Bit mask value 0x0001 passed to brix_http_etag_list_contains() and
 *      brix_http_check_etag_preconditions(). WHY: RFC 7232 §2.3 defines weak equivalence;
 *      callers use this flag when comparing If-None-Match headers against resource ETags. */

#define BRIX_HTTP_COND_WEAK_EQUIV  0x0001

/*
 * BRIX_HTTP_COND_READ / BRIX_HTTP_COND_TIME — mode flags for
 * brix_http_eval_preconditions().
 *
 * WHAT: READ selects GET/HEAD semantics — a matching If-None-Match yields
 *       304 Not Modified instead of 412, and If-Modified-Since is evaluated.
 *       TIME enables the date-based headers (If-Unmodified-Since, and with
 *       READ also If-Modified-Since); without it only the ETag headers are
 *       evaluated (the conditional-write contract: If-Match / If-None-Match).
 * WHY: RFC 9110 §13.1 gives If-None-Match different outcomes for reads vs
 *      writes, and conditional-write callers (S3 PutObject) must not grow
 *      date-header behaviour their protocol does not define. */

#define BRIX_HTTP_COND_READ        0x0002
#define BRIX_HTTP_COND_TIME        0x0004

/*
 * brix_http_etag_list_contains - check whether an ETag header value matches a target ETag.
 *
 * WHAT: Scans the ETag header string for occurrences of the target etag value,
 *       respecting weak equivalence flags (BRIX_HTTP_COND_WEAK_EQUIV).
 *
 * WHY: HTTP conditional requests (If-None-Match / If-Match) carry ETag lists.
 *      The server must check whether any entry in the list matches the resource
 *      ETag to decide between 304 Not Modified and full response.
 *
 * HOW: Strips weak-prefix markers from header entries when flags include WEAK_EQUIV,
 *      then compares each entry against the target etag string.
 */
ngx_int_t brix_http_etag_list_contains(const ngx_str_t *header,
    const char *etag, unsigned flags);

/*
 * brix_http_check_etag_preconditions - evaluate If-None-Match / If-Match against resource ETag.
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
 * HOW: Generates resource ETag from mtime/size via brix_http_etag_str(), then checks
 *      against the If-None-Match / If-Match header using brix_http_etag_list_contains().
 */
ngx_int_t brix_http_check_etag_preconditions(ngx_http_request_t *r,
    ngx_flag_t resource_exists, const struct stat *st, unsigned etag_flags,
    unsigned condition_flags);

/*
 * brix_http_eval_preconditions - full RFC 9110 §13.2.2 precondition evaluation.
 *
 * WHAT: Evaluates If-Match, If-Unmodified-Since, If-None-Match, and
 *       If-Modified-Since in the RFC-mandated precedence order against the
 *       resource's synthetic ETag (mtime+size) and mtime. Returns NGX_OK when
 *       every precondition passes, NGX_HTTP_NOT_MODIFIED (304, READ mode only)
 *       when If-None-Match / If-Modified-Since short-circuits a read, or
 *       NGX_HTTP_PRECONDITION_FAILED (412) on any failed precondition.
 *
 * WHY: One evaluator owns the precedence rules and the read/write outcome
 *      split so S3 GET/HEAD, S3 conditional PUT, and future WebDAV callers
 *      cannot drift apart. (brix_http_check_etag_preconditions above is the
 *      ETag-only WebDAV-write subset and predates this entry point.)
 *
 * HOW: Precedence per RFC 9110 §13.2.2 — If-Match, else If-Unmodified-Since
 *      (TIME mode); then If-None-Match, else If-Modified-Since (READ+TIME
 *      mode, `before` semantics: unmodified since the date ⇒ 304). Empty
 *      header values are treated as absent. `*` matches any existing
 *      representation; list matching uses brix_http_etag_list_contains()
 *      with `condition_flags` weak-equivalence passed through. The resource
 *      ETag is derived from mtime/size via brix_http_etag_str(etag_flags)
 *      only when resource_exists.
 */
ngx_int_t brix_http_eval_preconditions(ngx_http_request_t *r,
    ngx_flag_t resource_exists, time_t mtime, off_t size,
    unsigned etag_flags, unsigned condition_flags);

/*
 * brix_http_check_if_modified_since - evaluate If-Modified-Since / If-Unmodified-Since.
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
ngx_int_t brix_http_check_if_modified_since(ngx_http_request_t *r,
    time_t mtime);

/*
 * brix_http_overwrite_forbidden - check whether Over: false header forbids overwrite.
 *
 * WHAT: Returns NGX_TRUE if the HTTP Over header is "false" and the target resource
 *       already exists, indicating the client does not want to overwrite existing data.
 *
 * WHY: WebDAV RFC 4918 §9.9 defines the Over header to control overwrite behaviour on
 *      PUT/MOVE/COPY. Servers must respect Over: false by returning 412 Precondition Failed
 *      when the target exists.
 *
 * HOW: Looks up the Over header via brix_http_find_header(), checks value equals "false"
 *      (case-insensitive, trimmed), and verifies resource_exists flag.
 */
ngx_flag_t brix_http_overwrite_forbidden(ngx_http_request_t *r);

#endif /* BRIX_COMPAT_HTTP_CONDITIONALS_H */
