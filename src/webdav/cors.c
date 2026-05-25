/*
 * cors.c — WebDAV CORS wrapper around the shared compat helper.
 *
 * webdav_add_cors_headers() is the single entry point for all WebDAV
 * handlers.  It:
 *   1. Fetches the WebDAV loc_conf.
 *   2. Builds the Allow-Methods string from the WebDAV operation table.
 *   3. Populates an xrootd_cors_conf_t and delegates to xrootd_http_add_cors_headers().
 *   4. Maps the return code to WebDAV CORS metrics and nginx return values.
 *
 * Protocol-agnostic origin matching and header emission live in
 * src/compat/cors.c; nothing WebDAV-specific belongs there.
 */

#include "webdav.h"
#include "../compat/cors.h"

ngx_int_t
webdav_add_cors_headers(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *wlcf;
    xrootd_cors_conf_t                 cors;
    ngx_int_t                          rc;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    cors.origins     = wlcf->cors_origins;
    cors.credentials = wlcf->cors_credentials;
    cors.max_age     = wlcf->cors_max_age;

    if (xrootd_http_operation_allow_header(r->pool,
            xrootd_webdav_operations, xrootd_webdav_operations_count,
            XROOTD_WEBDAV_ALLOW_FLAGS(wlcf), &cors.allow_methods) != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = xrootd_http_add_cors_headers(r, &cors);

    switch (rc) {
    case NGX_OK:
        XROOTD_WEBDAV_METRIC_INC(cors_total[XROOTD_WEBDAV_CORS_ALLOWED]);
        return NGX_OK;

    case NGX_DECLINED:
        /* Distinguish "no Origin header" from "origin denied" for metrics. */
        if (xrootd_http_find_header(r, "Origin",
                                    sizeof("Origin") - 1) == NULL)
        {
            if (wlcf->cors_origins != NULL
                && wlcf->cors_origins->nelts > 0)
            {
                XROOTD_WEBDAV_METRIC_INC(
                    cors_total[XROOTD_WEBDAV_CORS_NO_ORIGIN]);
            }
        } else {
            XROOTD_WEBDAV_METRIC_INC(cors_total[XROOTD_WEBDAV_CORS_DENIED]);
        }
        return NGX_OK;

    default: /* NGX_ERROR */
        return NGX_ERROR;
    }
}
