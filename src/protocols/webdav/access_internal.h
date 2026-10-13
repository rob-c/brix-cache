/*
 * access_internal.h - private split contract between access.c and its
 * access-phase siblings (access_auth.c).  Not a public API: include only
 * from src/protocols/webdav/.  See docs/refactor/phase-38-file-size-unix-
 * modularity.md for the split rationale.
 */
#ifndef BRIX_WEBDAV_ACCESS_INTERNAL_H
#define BRIX_WEBDAV_ACCESS_INTERNAL_H

#include "webdav.h"   /* ngx_http_request_t, ngx_http_brix_webdav_loc_conf_t */

/* access_auth.c - the authentication gate.
 *
 * Runs the credential sources in order (GSI proxy cert, bearer token, then
 * Basic password) and applies the location's auth policy to the outcome.
 * Returns NGX_OK to continue (authenticated or anonymous) or the
 * metrics-counted rejection. */
ngx_int_t access_authenticate(ngx_http_request_t *r,
                              ngx_http_brix_webdav_loc_conf_t *conf);

/* access_query.c - the single parsed query and XrdHttp preparation boundary. */
ngx_int_t access_parse_query_boundary(ngx_http_request_t *r);
ngx_int_t access_prepare_xrdhttp(ngx_http_request_t *r);

#endif /* BRIX_WEBDAV_ACCESS_INTERNAL_H */
