/*
 * authz_endpoint.h — the gate-only content handlers (phase-106 W3/W4).
 *
 * WHAT: Declares the auth_request target (brix_webdav_authz) and the
 *       X-Accel-Redirect handoff (brix_webdav_accel_redirect).
 *
 * WHY:  Both let brix gate a location it does not serve, so its WLCG/VOMS/
 *       macaroon/GSI authorization can front an existing nginx deployment.
 *
 * HOW:  Both run in the CONTENT phase — i.e. only after the ACCESS phase has
 *       already admitted the request — so they REPORT the verdict and never
 *       recompute it. See authz_endpoint.c for the full security reasoning.
 */
#ifndef BRIX_WEBDAV_AUTHZ_ENDPOINT_H
#define BRIX_WEBDAV_AUTHZ_ENDPOINT_H

#include "webdav.h"

ngx_int_t webdav_authz_endpoint(ngx_http_request_t *r);
ngx_int_t webdav_accel_redirect(ngx_http_request_t *r,
                                const ngx_str_t *prefix);

/* Runs whichever seam the location configures; NGX_DECLINED when neither is. */
ngx_int_t webdav_gate_only_dispatch(ngx_http_request_t *r,
                                    ngx_http_brix_webdav_loc_conf_t *conf);

#endif /* BRIX_WEBDAV_AUTHZ_ENDPOINT_H */
