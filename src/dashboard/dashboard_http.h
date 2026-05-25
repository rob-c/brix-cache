#ifndef XROOTD_DASHBOARD_HTTP_H
#define XROOTD_DASHBOARD_HTTP_H

/*
 * dashboard/dashboard_http.h - HTTP-module-only declarations for the live monitor.
 *
 * This header is included ONLY by the HTTP dashboard module source files
 * (module.c, auth.c, api.c, page.c).  It must NOT be included from any file
 * that is compiled as part of the stream module because ngx_http_request_t
 * is not available in the stream compilation context.
 *
 * The stream-visible types and slot operations are in dashboard.h, which is
 * included through the umbrella ngx_xrootd_module.h.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "dashboard.h"
#include "../metrics/metrics.h"

/* The nginx HTTP module object - defined in module.c */
extern ngx_module_t ngx_http_xrootd_dashboard_module;

/* Per-location config struct */
typedef struct {
    ngx_str_t username;
    ngx_str_t password_hash;
} ngx_http_xrootd_dashboard_user_t;

typedef struct {
    ngx_flag_t  enable;
    ngx_str_t   password;       /* plaintext from xrootd_dashboard_password directive */
    ngx_uint_t  session_ttl;    /* cookie lifetime in seconds; default 28800 (8 h)    */
    ngx_msec_t  idle_threshold_ms;
    ngx_msec_t  stalled_threshold_ms;
    ngx_msec_t  cluster_stale_after_ms;
    ngx_str_t   cookie_path;    /* Set-Cookie Path and post-login redirect base       */
    ngx_array_t *users;         /* ngx_http_xrootd_dashboard_user_t entries           */
} ngx_http_xrootd_dashboard_loc_conf_t;

typedef enum {
    XROOTD_DASHBOARD_API_COMPAT_TRANSFERS = 0,
    XROOTD_DASHBOARD_API_V1_TRANSFERS,
    XROOTD_DASHBOARD_API_V1_TRANSFER_DETAIL,
    XROOTD_DASHBOARD_API_V1_SNAPSHOT,
    XROOTD_DASHBOARD_API_V1_EVENTS,
    XROOTD_DASHBOARD_API_V1_HISTORY,
    XROOTD_DASHBOARD_API_V1_CLUSTER,
    XROOTD_DASHBOARD_API_V1_CACHE,
    XROOTD_DASHBOARD_API_V1_NOT_FOUND
} xrootd_dashboard_api_endpoint_e;

/* HTTP content handlers */
ngx_int_t ngx_http_xrootd_dashboard_main_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_xrootd_dashboard_api_handler(ngx_http_request_t *r,
    xrootd_dashboard_api_endpoint_e endpoint);
ngx_int_t ngx_http_xrootd_dashboard_page_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_xrootd_dashboard_login_handler(ngx_http_request_t *r);

/*
 * Check if the request carries a valid xrd_dashboard cookie.
 * Returns NGX_OK if valid, NGX_HTTP_UNAUTHORIZED otherwise.
 */
ngx_int_t ngx_http_xrootd_dashboard_check_auth(ngx_http_request_t *r,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf);

#endif /* XROOTD_DASHBOARD_HTTP_H */
