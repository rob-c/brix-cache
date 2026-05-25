/*
 * cors.c — protocol-agnostic HTTP CORS response header helper.
 *
 * Implements xrootd_http_add_cors_headers() using only the fields in
 * xrootd_cors_conf_t — no WebDAV, S3, or stream-specific code lives here.
 *
 * See cors.h for the API contract and return-value semantics.
 */

#include "cors.h"
#include "http_headers.h"

/*
 * origin_allowed — check origin against the allowlist.
 *
 * Sets *wildcard=1 when a bare "*" entry matched.  Returns 1 if allowed,
 * 0 if not.
 */
static ngx_int_t
origin_allowed(const xrootd_cors_conf_t *cors,
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

ngx_int_t
xrootd_http_add_cors_headers(ngx_http_request_t *r,
    const xrootd_cors_conf_t *cors)
{
    ngx_table_elt_t  *origin_hdr;
    ngx_table_elt_t  *req_headers;
    ngx_str_t         origin;
    ngx_str_t         max_age;
    u_char           *p;
    u_char            age_buf[NGX_INT_T_LEN];
    ngx_flag_t        wildcard;

    origin_hdr = xrootd_http_find_header(r, "Origin", sizeof("Origin") - 1);
    if (origin_hdr == NULL) {
        return NGX_DECLINED;
    }

    origin = origin_hdr->value;
    if (!origin_allowed(cors, &origin, &wildcard)) {
        return NGX_DECLINED;
    }

    /* Access-Control-Allow-Origin: echo origin or "*" for non-credentialed wildcard. */
    if (wildcard && !cors->credentials) {
        if (xrootd_http_set_header(r, "Access-Control-Allow-Origin", "*", NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else {
        if (xrootd_http_set_header_str(r, "Access-Control-Allow-Origin",
                                       &origin, 0, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (xrootd_http_set_header(r, "Vary", "Origin", NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cors->allow_methods.len > 0) {
        if (xrootd_http_set_header_str(r, "Access-Control-Allow-Methods",
                                       &cors->allow_methods, 0, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (xrootd_http_set_header(r, "Access-Control-Expose-Headers",
                               "Content-Length, Content-Range, Content-Type, "
                               "DAV, ETag, Last-Modified, Location, Digest",
                               NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (cors->credentials) {
        if (xrootd_http_set_header(r, "Access-Control-Allow-Credentials",
                                   "true", NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /* Echo Access-Control-Allow-Headers from the preflight request if present
     * and safe; otherwise fall back to the standard set. */
    req_headers = xrootd_http_find_header(
        r, "Access-Control-Request-Headers",
        sizeof("Access-Control-Request-Headers") - 1);
    if (req_headers != NULL
        && !xrootd_http_str_has_ctl(req_headers->value.data,
                                    req_headers->value.len))
    {
        if (xrootd_http_set_header_str(r, "Access-Control-Allow-Headers",
                                       &req_headers->value, 0, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else {
        if (xrootd_http_set_header(r, "Access-Control-Allow-Headers",
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
    }

    p = ngx_snprintf(age_buf, sizeof(age_buf), "%ui", cors->max_age);
    max_age.len  = (size_t) (p - age_buf);
    max_age.data = ngx_pnalloc(r->pool, max_age.len);
    if (max_age.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(max_age.data, age_buf, max_age.len);

    return xrootd_http_set_header_str(r, "Access-Control-Max-Age",
                                      &max_age, 0, NULL);
}
