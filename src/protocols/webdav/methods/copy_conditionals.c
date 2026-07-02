/*
 * copy_conditionals.c - RFC 9110 conditional checks for WebDAV COPY.
 *
 * WHAT: Evaluates HTTP conditional headers (If-Match / If-None-Match) against the
 *       destination resource during a COPY operation, preventing overwrites when the
 *       client expects a specific resource state or wants to avoid replacing existing content.
 *
 * WHY: RFC 9110 §13.1.2 defines conditional request semantics for safe operations. COPY
 *      without conditionals can silently overwrite concurrent modifications — conditionals
 *      provide optimistic concurrency control preventing data loss in multi-client scenarios.
 *
 * HOW: Delegates the ETag list parsing and wildcard semantics to the shared
 *      HTTP conditional helper, keeping this file as the COPY-specific wrapper
 *      that logs destination context.
 */

#include "copy_conditionals.h"
#include "core/http/etag.h"
#include "core/http/http_conditionals.h"

/*
 * WHAT: Evaluate HTTP conditional headers (If-Match / If-None-Match) against the COPY
 *       destination resource to enforce optimistic concurrency — prevent overwrites when
 *       client expects specific state or wants to avoid replacing existing content.
 *
 * WHY: Without conditionals, a COPY can silently overwrite concurrent modifications by other
 *      clients. RFC 9110 §13.1.2 provides two mechanisms: If-Match (destination must match ETag)
 *      for "overwrite only if unchanged" semantics; If-None-Match (destination must not exist/match)
 *      for "create-only / skip-if-exists" semantics. Both return 412 Precondition Failed on mismatch.
 *
 * HOW: First, generate destination ETag from stat metadata (mtime + size) via `webdav_etag_str()`.
 *      Then evaluate each header independently: If-Match requires exact ETag match or "*" wildcard;
 *      If-None-Match passes when destination absent OR ETag doesn't match OR "*" wildcard against
 *      non-existent resource. Both headers checked together — either can pass the precondition.
 */
ngx_int_t
webdav_check_copy_conditionals(ngx_http_request_t *r,
    const char *dst_path, int dst_exists, const struct stat *dst_sb)
{
    ngx_int_t rc;

    rc = xrootd_http_check_etag_preconditions(
        r, dst_exists, dst_sb, XROOTD_ETAG_WEAK, 0);
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrootd_webdav COPY: conditional failed for %s",
                       dst_path);
    }

    return rc;
}
