/*
 * cors.c - configurable WebDAV CORS response headers.
 */

#include "webdav.h"

static ngx_int_t
webdav_add_header(ngx_http_request_t *r, const char *name,
                  const char *value)
{
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = ngx_strlen(name);
    h->key.data = (u_char *) name;
    h->value.len = ngx_strlen(value);
    h->value.data = (u_char *) value;

    return NGX_OK;
}

static ngx_int_t
webdav_add_header_str(ngx_http_request_t *r, const char *name,
                      const ngx_str_t *value)
{
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = ngx_strlen(name);
    h->key.data = (u_char *) name;
    h->value = *value;

    return NGX_OK;
}

static const char *
webdav_cors_methods(ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    if (conf->allow_write && conf->tpc) {
        return "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, PROPFIND";
    }

    if (conf->allow_write) {
        return "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND";
    }

    return "OPTIONS, GET, HEAD, PROPFIND";
}

static ngx_int_t
webdav_cors_origin_allowed(ngx_http_xrootd_webdav_loc_conf_t *conf,
                           ngx_str_t *origin, ngx_flag_t *wildcard)
{
    ngx_str_t  *origins;
    ngx_uint_t  i;

    *wildcard = 0;

    if (conf->cors_origins == NULL || conf->cors_origins->nelts == 0) {
        return 0;
    }

    origins = conf->cors_origins->elts;
    for (i = 0; i < conf->cors_origins->nelts; i++) {
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
webdav_add_cors_headers(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t                   *origin_hdr;
    ngx_table_elt_t                   *request_headers;
    ngx_str_t                          origin;
    ngx_str_t                          max_age;
    u_char                            *p;
    u_char                             age_buf[NGX_INT_T_LEN];
    ngx_flag_t                         wildcard;
    ngx_int_t                          rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    origin_hdr = webdav_tpc_find_header(r, "Origin", sizeof("Origin") - 1);
    if (origin_hdr == NULL) {
        if (conf->cors_origins != NULL && conf->cors_origins->nelts > 0) {
            XROOTD_WEBDAV_METRIC_INC(cors_total[XROOTD_WEBDAV_CORS_NO_ORIGIN]);
        }
        return NGX_OK;
    }

    origin = origin_hdr->value;
    if (!webdav_cors_origin_allowed(conf, &origin, &wildcard)) {
        XROOTD_WEBDAV_METRIC_INC(cors_total[XROOTD_WEBDAV_CORS_DENIED]);
        return NGX_OK;
    }

    XROOTD_WEBDAV_METRIC_INC(cors_total[XROOTD_WEBDAV_CORS_ALLOWED]);

    if (wildcard && !conf->cors_credentials) {
        rc = webdav_add_header(r, "Access-Control-Allow-Origin", "*");
    } else {
        rc = webdav_add_header_str(r, "Access-Control-Allow-Origin",
                                   &origin);
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (webdav_add_header(r, "Vary", "Origin") != NGX_OK
        || webdav_add_header(r, "Access-Control-Allow-Methods",
                             webdav_cors_methods(conf)) != NGX_OK
        || webdav_add_header(r, "Access-Control-Expose-Headers",
                             "Content-Length, Content-Range, Content-Type, "
                             "DAV, ETag, Last-Modified, Location, Digest")
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (conf->cors_credentials) {
        if (webdav_add_header(r, "Access-Control-Allow-Credentials", "true")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    request_headers = webdav_tpc_find_header(
        r, "Access-Control-Request-Headers",
        sizeof("Access-Control-Request-Headers") - 1);
    if (request_headers != NULL
        && !webdav_tpc_str_has_ctl(request_headers->value.data,
                                   request_headers->value.len))
    {
        if (webdav_add_header_str(r, "Access-Control-Allow-Headers",
                                  &request_headers->value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else if (webdav_add_header(r, "Access-Control-Allow-Headers",
                                 "Authorization, Content-Type, "
                                 "Content-Length, Depth, Destination, Source, "
                                 "Overwrite, Credential, Credentials, "
                                 "TransferHeaderAuthorization, "
                                 "TransferHeaderCookie, Want-Digest, Digest, "
                                 "Range, If-Match, If-None-Match, "
                                 "If-Modified-Since, If-Unmodified-Since")
               != NGX_OK)
    {
        return NGX_ERROR;
    }

    p = ngx_snprintf(age_buf, sizeof(age_buf), "%ui", conf->cors_max_age);
    max_age.data = ngx_pnalloc(r->pool, (size_t) (p - age_buf));
    if (max_age.data == NULL) {
        return NGX_ERROR;
    }
    max_age.len = (size_t) (p - age_buf);
    ngx_memcpy(max_age.data, age_buf, max_age.len);

    return webdav_add_header_str(r, "Access-Control-Max-Age", &max_age);
}
