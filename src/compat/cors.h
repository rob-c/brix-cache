/*
 * cors.h — protocol-agnostic HTTP CORS response header helper.
 *
 * Provides xrootd_cors_conf_t (a plain config struct) and
 * xrootd_http_add_cors_headers() so both WebDAV and S3 (when CORS support is
 * added) can share the same Origin-matching and header-emission logic without
 * duplicating it in each protocol module.
 *
 * WHY: WebDAV CORS was previously implemented entirely in src/webdav/cors.c.
 *      Moving the protocol-agnostic core here lets S3 add CORS support by
 *      populating an xrootd_cors_conf_t and calling xrootd_http_add_cors_headers()
 *      without touching WebDAV code.
 */

#ifndef XROOTD_COMPAT_CORS_H
#define XROOTD_COMPAT_CORS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * xrootd_cors_conf_t — protocol-agnostic CORS policy for one location.
 *
 * Populate from your protocol's loc_conf before calling
 * xrootd_http_add_cors_headers().  Both WebDAV and S3 store the same
 * four fields; embedding or copying into this struct is cheap.
 *
 * origins    — ngx_str_t[] of allowed Origin values; a single-char "*"
 *              entry acts as a wildcard.  NULL or zero-length array disables CORS.
 * credentials — if 1, emit Access-Control-Allow-Credentials: true and echo
 *              the specific origin even for wildcard configs (RFC 6454 §7.2).
 * max_age    — Access-Control-Max-Age value in seconds (typically 86400).
 * allow_methods — pre-built comma-separated methods string, e.g.
 *              "GET, PUT, DELETE, OPTIONS, HEAD, PROPFIND".  Caller builds
 *              this from the protocol's operation table.
 */
typedef struct {
    ngx_array_t  *origins;
    ngx_flag_t    credentials;
    ngx_uint_t    max_age;
    ngx_str_t     allow_methods;
} xrootd_cors_conf_t;

/*
 * xrootd_http_add_cors_headers — emit CORS response headers for a request.
 *
 * WHAT: Validates the request's Origin header against cors->origins; if
 *       allowed, emits Access-Control-Allow-Origin, Vary: Origin,
 *       Access-Control-Allow-Methods, Access-Control-Expose-Headers,
 *       optionally Access-Control-Allow-Credentials, Access-Control-Allow-Headers
 *       (echoed from the request or a safe default set), and Access-Control-Max-Age.
 *
 * WHY: All HTTP-based protocols (WebDAV, S3) share the same CORS header
 *      emission rules (RFC 6454 / Fetch spec).  A single implementation
 *      prevents drift between protocols and makes future CORS changes apply
 *      everywhere at once.
 *
 * Return values:
 *   NGX_OK       — Origin was allowed; headers were added to r->headers_out.
 *   NGX_DECLINED — No Origin header, or origin not in the allowlist; no
 *                  headers were emitted (caller should continue normally).
 *   NGX_ERROR    — Pool allocation failed (treat as 500).
 *
 * The caller is responsible for incrementing any protocol-specific CORS
 * metrics based on the return value (NGX_OK = allowed, NGX_DECLINED = denied
 * or no origin).
 */
ngx_int_t xrootd_http_add_cors_headers(ngx_http_request_t *r,
    const xrootd_cors_conf_t *cors);

#endif /* XROOTD_COMPAT_CORS_H */
