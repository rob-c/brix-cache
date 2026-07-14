/*
 * cors.c — WebDAV CORS header emission.
 *
 * webdav_add_cors_headers() is the single entry point for all WebDAV handlers.
 */

#include "webdav.h"

typedef struct {
    ngx_array_t  *origins;
    ngx_flag_t    credentials;
    ngx_uint_t    max_age;
    ngx_str_t     allow_methods;
} brix_cors_conf_t;

/*
 * Match the request Origin against the configured allowlist.
 * Returns 1 if allowed and sets *wildcard when the match was the "*" entry
 * (which later forces echo-vs-"*" handling against the credentials flag).
 * An empty/unset allowlist denies everything: CORS is opt-in.
 */
static ngx_int_t
origin_allowed(const brix_cors_conf_t *cors,
               const ngx_str_t *origin, ngx_flag_t *wildcard)
{
    ngx_str_t  *origins;
    ngx_uint_t  i;

    *wildcard = 0;

    if (cors->origins == NULL || cors->origins->nelts == 0) {
        return 0;
    }

    origins = cors->origins->elts;
    for (i = 0; i < cors->origins->nelts; i++) {
        if (origins[i].len == 1 && origins[i].data[0] == '*') {
            *wildcard = 1;
            return 1;
        }
        if (origins[i].len == origin->len
            && ngx_strncmp(origins[i].data, origin->data, origin->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}

/* ---- Emit the Access-Control-Allow-Origin (+Vary) header pair ----
 *
 * WHAT: Sets Access-Control-Allow-Origin to the literal "*" only for a
 *       non-credentialed wildcard match, otherwise echoes the concrete request
 *       origin; always adds Vary: Origin. Returns NGX_OK, or NGX_ERROR on a
 *       header-set failure.
 *
 * WHY:  Preserves the CORS security rule intact in one place: the literal "*"
 *       is forbidden together with credentials, so when credentials are on the
 *       concrete origin must be echoed even for a "*" allowlist entry. Vary:
 *       Origin keeps caches from leaking one origin's response to another.
 *
 * HOW:  1. If the match was wildcard and credentials are off, set the "*"
 *          value; otherwise echo the request origin verbatim.
 *       2. Add Vary: Origin.
 *       3. Return NGX_ERROR if any set failed, else NGX_OK.
 */
static ngx_int_t
cors_emit_allow_origin(ngx_http_request_t *r, const brix_cors_conf_t *cors,
    const ngx_str_t *origin, ngx_flag_t wildcard)
{
    if (wildcard && !cors->credentials) {
        if (brix_http_set_header(r, "Access-Control-Allow-Origin", "*", NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else {
        if (brix_http_set_header_str(r, "Access-Control-Allow-Origin",
                                       origin, 0, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (brix_http_set_header(r, "Vary", "Origin", NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Emit Allow-Methods, Expose-Headers and Allow-Credentials ----
 *
 * WHAT: Sets Access-Control-Allow-Methods (only when a non-empty method list is
 *       configured), the fixed Access-Control-Expose-Headers set, and
 *       Access-Control-Allow-Credentials: true (only when credentials are on).
 *       Returns NGX_OK, or NGX_ERROR on a header-set failure.
 *
 * WHY:  Groups the three unconditional-value headers whose emission depends
 *       only on configuration, keeping the orchestrator flat without changing
 *       which headers are produced.
 *
 * HOW:  1. If a method list is configured, emit Allow-Methods.
 *       2. Emit the fixed Expose-Headers list.
 *       3. If credentials are enabled, emit Allow-Credentials: true.
 */
static ngx_int_t
cors_emit_methods_and_flags(ngx_http_request_t *r, const brix_cors_conf_t *cors)
{
    if (cors->allow_methods.len > 0) {
        if (brix_http_set_header_str(r, "Access-Control-Allow-Methods",
                                       &cors->allow_methods, 0, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (brix_http_set_header(r, "Access-Control-Expose-Headers",
                               "Content-Length, Content-Range, Content-Type, "
                               "DAV, ETag, Last-Modified, Location, Digest",
                               NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (cors->credentials) {
        if (brix_http_set_header(r, "Access-Control-Allow-Credentials",
                                   "true", NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* ---- Emit the Access-Control-Allow-Headers header ----
 *
 * WHAT: Echoes the preflight Access-Control-Request-Headers value when it is
 *       present and free of control characters, otherwise emits the standard
 *       fallback header set. Returns NGX_OK, or NGX_ERROR on a set failure.
 *
 * WHY:  Untrusted request header bytes must never be reflected unchecked:
 *       echoing CR/LF or other control bytes would allow response header
 *       injection, so the echo path is gated on a control-character scan.
 *
 * HOW:  1. Find the Access-Control-Request-Headers request header.
 *       2. If present and control-character-free, echo its value verbatim.
 *       3. Otherwise emit the fixed fallback allow-headers list.
 */
static ngx_int_t
cors_emit_allow_headers(ngx_http_request_t *r)
{
    ngx_table_elt_t  *req_headers;

    req_headers = brix_http_find_header(
        r, "Access-Control-Request-Headers",
        sizeof("Access-Control-Request-Headers") - 1);

    if (req_headers != NULL
        && !brix_http_str_has_ctl(req_headers->value.data,
                                    req_headers->value.len))
    {
        if (brix_http_set_header_str(r, "Access-Control-Allow-Headers",
                                       &req_headers->value, 0, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    if (brix_http_set_header(r, "Access-Control-Allow-Headers",
                               "Authorization, Content-Type, "
                               "Content-Length, Depth, Destination, Source, "
                               "Overwrite, Credential, Credentials, "
                               "TransferHeaderAuthorization, "
                               "TransferHeaderCookie, Want-Digest, Digest, "
                               "Range, If-Match, If-None-Match, "
                               "If-Modified-Since, If-Unmodified-Since",
                               NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Emit the Access-Control-Max-Age header ----
 *
 * WHAT: Renders the configured max-age as a decimal string into a pool
 *       allocation and sets Access-Control-Max-Age. Returns the set result
 *       (NGX_OK/NGX_ERROR), or NGX_ERROR on allocation failure.
 *
 * WHY:  The value is a runtime integer that must outlive this frame as an
 *       ngx_str_t, so it is formatted into a request-pool buffer before the
 *       header is set.
 *
 * HOW:  1. Format cors->max_age into a stack buffer.
 *       2. Copy it into a request-pool allocation.
 *       3. Set the header from the pool-backed ngx_str_t.
 */
static ngx_int_t
cors_emit_max_age(ngx_http_request_t *r, const brix_cors_conf_t *cors)
{
    ngx_str_t  max_age;
    u_char    *p;
    u_char     age_buf[NGX_INT_T_LEN];

    p = ngx_snprintf(age_buf, sizeof(age_buf), "%ui", cors->max_age);
    max_age.len  = (size_t) (p - age_buf);
    max_age.data = ngx_pnalloc(r->pool, max_age.len);
    if (max_age.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(max_age.data, age_buf, max_age.len);

    return brix_http_set_header_str(r, "Access-Control-Max-Age",
                                      &max_age, 0, NULL);
}

/*
 * Emit the Access-Control-* response headers for an allowed cross-origin
 * request.  Returns NGX_DECLINED (no headers, not an error) when there is no
 * Origin header or the origin is not allowed; NGX_OK when headers were set;
 * NGX_ERROR only on allocation/header-set failure.
 */
static ngx_int_t
brix_http_add_cors_headers(ngx_http_request_t *r,
    const brix_cors_conf_t *cors)
{
    ngx_table_elt_t  *origin_hdr;
    ngx_str_t         origin;
    ngx_flag_t        wildcard;

    origin_hdr = brix_http_find_header(r, "Origin", sizeof("Origin") - 1);
    if (origin_hdr == NULL) {
        return NGX_DECLINED;
    }

    origin = origin_hdr->value;
    if (!origin_allowed(cors, &origin, &wildcard)) {
        return NGX_DECLINED;
    }

    if (cors_emit_allow_origin(r, cors, &origin, wildcard) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cors_emit_methods_and_flags(r, cors) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cors_emit_allow_headers(r) != NGX_OK) {
        return NGX_ERROR;
    }

    return cors_emit_max_age(r, cors);
}

/*
 * WHAT: Sole CORS entry point for every WebDAV handler (see HELPERS).
 * HOW:  Snapshots the location's CORS config, derives the Allow-Methods list
 *       from the live operation table (so it matches the actual enabled verbs),
 *       emits the headers, and records an allowed/denied/no-origin metric.
 *       NGX_DECLINED from the worker is intentionally folded into NGX_OK: a
 *       request with no/disallowed Origin is still a valid request, just one
 *       that gets no CORS headers.
 */
ngx_int_t
webdav_add_cors_headers(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf;
    brix_cors_conf_t                 cors;
    ngx_int_t                          rc;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    cors.origins     = wlcf->cors_origins;
    cors.credentials = wlcf->cors_credentials;
    cors.max_age     = wlcf->cors_max_age;

    if (brix_http_operation_allow_header(r->pool,
            brix_webdav_operations, brix_webdav_operations_count,
            BRIX_WEBDAV_ALLOW_FLAGS(wlcf), &cors.allow_methods) != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = brix_http_add_cors_headers(r, &cors);

    switch (rc) {
    case NGX_OK:
        BRIX_WEBDAV_METRIC_INC(cors_total[BRIX_WEBDAV_CORS_ALLOWED]);
        return NGX_OK;

    case NGX_DECLINED:
        /* Distinguish "no Origin header" from "origin denied" for metrics. */
        if (brix_http_find_header(r, "Origin",
                                    sizeof("Origin") - 1) == NULL)
        {
            if (wlcf->cors_origins != NULL
                && wlcf->cors_origins->nelts > 0)
            {
                BRIX_WEBDAV_METRIC_INC(
                    cors_total[BRIX_WEBDAV_CORS_NO_ORIGIN]);
            }
        } else {
            BRIX_WEBDAV_METRIC_INC(cors_total[BRIX_WEBDAV_CORS_DENIED]);
        }
        return NGX_OK;

    default: /* NGX_ERROR */
        return NGX_ERROR;
    }
}
