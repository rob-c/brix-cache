#ifndef XROOTD_COMPAT_HTTP_QUERY_H
#define XROOTD_COMPAT_HTTP_QUERY_H

#include <ngx_config.h>
#include <ngx_core.h>

#define XROOTD_HTTP_QUERY_CASE_INSENSITIVE  0x0001u
#define XROOTD_HTTP_QUERY_DECODE_VALUE      0x0002u
#define XROOTD_HTTP_QUERY_PLUS_TO_SPACE     0x0004u
#define XROOTD_HTTP_QUERY_REJECT_NUL        0x0008u
#define XROOTD_HTTP_QUERY_ALLOW_EMPTY       0x0010u
#define XROOTD_HTTP_QUERY_TRUNCATE          0x0020u
#define XROOTD_HTTP_QUERY_HAS_VALUE_OK      0x0040u

/*
 * xrootd_http_query_get - parse a query string and extract value for key into buffer.
 *
 * WHAT: Searches args (e.g. r->args) for key=, extracts the value substring, optionally
 *       URL-decodes it (+ → space), rejects null bytes, truncates to outsz. Returns
 *       NGX_OK on success or NGX_ERROR/NGX_DECLINED on failure.
 *
 * WHY: WebDAV and S3 handlers extract URL parameters (e.g. ?versionId=XXX,
 *      ?partNumber=N). This function handles decoding, validation, and truncation
 *      in one call for both modules.
 *
 * HOW: Walks args byte-by-byte looking for key followed by '='. Extracts value substring,
 *      applies flags (case-insensitive match, URL decode, +→space, reject NUL,
 *      allow empty). Copies into out[0..outsz-1] with truncation if needed.
 */

int xrootd_http_query_get(ngx_str_t args, const char *key, char *out,
    size_t outsz, unsigned flags);

/*
 * xrootd_http_query_has - check whether a query string contains a named key.
 *
 * WHAT: Searches args for the presence of key= (value may be empty). Returns NGX_OK
 *       if found, NGX_DECLINED if absent. Flags control case sensitivity and
 *       whether an empty value counts as "present".
 *
 * WHY: S3 operations check ?versionId presence to distinguish versioned vs unversioned
 *      requests. WebDAV checks for optional parameters without needing their values.
 *
 * HOW: Walks args looking for key followed by '='. Returns NGX_OK on match with
 *      flags (case-insensitive, value-ok), NGX_DECLINED on absence.
 */

int xrootd_http_query_has(ngx_str_t args, const char *key, unsigned flags);

#endif /* XROOTD_COMPAT_HTTP_QUERY_H */
