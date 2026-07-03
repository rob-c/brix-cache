#ifndef BRIX_DASHBOARD_HTTP_H
#define BRIX_DASHBOARD_HTTP_H

/*
 * dashboard/dashboard_http.h - HTTP-module-only declarations for the live monitor.
 *
 * This header is included ONLY by the HTTP dashboard module source files
 * (module.c, auth.c, api.c, page.c).  It must NOT be included from any file
 * that is compiled as part of the stream module because ngx_http_request_t
 * is not available in the stream compilation context.
 *
 * The stream-visible types and slot operations are in dashboard.h, which is
 * included through the umbrella ngx_brix_module.h.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "dashboard.h"
#include "observability/metrics/metrics.h"

/* The nginx HTTP module object - defined in module.c */
extern ngx_module_t ngx_http_brix_dashboard_module;

/* Per-location config struct */
typedef struct {
    ngx_str_t username;
    ngx_str_t password_hash;
} ngx_http_brix_dashboard_user_t;

typedef struct {
    ngx_flag_t  enable;
    ngx_flag_t  anonymous;      /* [brix_dashboard_anonymous on] — serve read-only,
                                 * PII/secret-redacted stats WITHOUT login. Config
                                 * download, transfer-detail and admin stay auth-only. */
    ngx_str_t   password;       /* plaintext from brix_dashboard_password directive */
    ngx_uint_t  session_ttl;    /* cookie lifetime in seconds; default 28800 (8 h)    */
    ngx_msec_t  idle_threshold_ms;
    ngx_msec_t  stalled_threshold_ms;
    ngx_msec_t  cluster_stale_after_ms;
    ngx_str_t   cookie_path;    /* Set-Cookie Path and post-login redirect base       */
    ngx_array_t *users;         /* ngx_http_brix_dashboard_user_t entries           */

    /* ---- Phase 23: admin write API (/xrootd/api/v1/admin/...) ---- */
    ngx_array_t *admin_allow;     /* ngx_cidr_t[] — [brix_admin_allow <cidr...>]      */
    ngx_str_t   admin_secret;     /* bearer secret read from file at config time;
                                   * [brix_admin_secret /run/secrets/token]          */
    ngx_flag_t  admin_require_both; /* [brix_admin_require_both on] — CIDR AND secret */
    ngx_array_t *admin_proxy_allow; /* ngx_str_t[] allowed dynamic-proxy backend hosts;
                                     * [brix_admin_proxy_allow <host>...] (W6/E1).
                                     * NULL = unrestricted (back-compat).               */

    /* ---- admin file browser (/xrootd/api/v1/files + /download) ---- */
    ngx_str_t   browse_root;        /* [brix_dashboard_browse_root <path>] — root the
                                     * admin file viewer may list/download from.  Empty
                                     * = feature disabled (endpoints 404, UI hidden). */
    char        browse_root_canon[PATH_MAX]; /* realpath of browse_root (confinement
                                              * anchor); empty when disabled.          */

    /* ---- storage scan engine (/xrootd/api/v1/scan, src/scan/) ---- */
    ngx_str_t   scan_root;        /* [brix_scan_root <path>] — confinement root the
                                   * scan walks. Empty = feature disabled (404).      */
    char        scan_root_canon[PATH_MAX];  /* realpath of scan_root; empty=disabled  */
    ngx_flag_t  vfs_browse;       /* [brix_dashboard_vfs_browse on] — VFS export
                                     browser endpoints (/api/v1/vfs*); admin-auth,
                                     read-only, OFF by default (exposes stored
                                     user data through the dashboard) */
    ngx_uint_t  scan_max_files;   /* [brix_scan_max_files <n>] cap on files visited
                                   * per request (default 100000)                     */
} ngx_http_brix_dashboard_loc_conf_t;

/* Admin file browser handlers (dashboard/files.c).  Both are admin-auth-only and
 * confined to browse_root_canon via openat2 RESOLVE_BENEATH. */
ngx_int_t ngx_http_brix_dashboard_files_handler(ngx_http_request_t *r);
/* VFS export browser (vfs_browse.c): census / listing / download through
 * brix_vfs_* — the logical namespace of ANY registered backend. */
ngx_int_t ngx_http_brix_dashboard_vfs_exports_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_brix_dashboard_vfs_files_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_brix_dashboard_vfs_download_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_brix_dashboard_download_handler(ngx_http_request_t *r);

/* Storage-scan handler (src/scan/scan_http.c). Admin-auth-only, confined to
 * scan_root_canon via openat2 RESOLVE_BENEATH. */
ngx_int_t ngx_http_brix_dashboard_scan_handler(ngx_http_request_t *r);

typedef enum {
    BRIX_DASHBOARD_API_COMPAT_TRANSFERS = 0,
    BRIX_DASHBOARD_API_V1_TRANSFERS,
    BRIX_DASHBOARD_API_V1_TRANSFER_DETAIL,
    BRIX_DASHBOARD_API_V1_SNAPSHOT,
    BRIX_DASHBOARD_API_V1_EVENTS,
    BRIX_DASHBOARD_API_V1_HISTORY,
    BRIX_DASHBOARD_API_V1_CLUSTER,
    BRIX_DASHBOARD_API_V1_CACHE,
    BRIX_DASHBOARD_API_V1_RATELIMIT,   /* Phase 25 */
    BRIX_DASHBOARD_API_V1_CVMFS,       /* phase-68 cvmfs:// site cache */
    BRIX_DASHBOARD_API_V1_NOT_FOUND
} brix_dashboard_api_endpoint_e;

/* HTTP content handlers */

/*
 * Top-level content handler installed on the dashboard location; routes by
 * r->uri (longest-match first) to the api/login/page handler or the admin
 * write API, with per-endpoint auth done downstream (NOT here).
 * Returns NGX_HTTP_NOT_FOUND when the module is disabled or the URI matches
 * no route; otherwise the chosen handler's return value (NGX_HTTP_* status,
 * output-filter result, or NGX_DONE for async bodies).
 */
ngx_int_t ngx_http_brix_dashboard_main_handler(ngx_http_request_t *r);

/*
 * Build and emit one JSON dashboard endpoint selected by endpoint.
 * Enforces cookie auth FIRST, then allows only GET/HEAD (else
 * NGX_HTTP_NOT_ALLOWED). Samples the history ring and totals as a side effect.
 * A NULL builder result degrades to a 507 body and logs a dashboard event;
 * detail/not-found endpoints may set their own 404. Returns the auth failure
 * code, NGX_HTTP_NOT_ALLOWED, or the output-filter result.
 */
ngx_int_t ngx_http_brix_dashboard_api_handler(ngx_http_request_t *r,
    brix_dashboard_api_endpoint_e endpoint);

/*
 * Serve the embedded single-page dashboard HTML asset.
 * On auth failure emits a 302 to "<cookie_path>/login" (allocated in r->pool)
 * instead of leaking the shell; rejects non-GET/HEAD.
 * Returns an NGX_HTTP_* status on redirect/error, or the output-filter result.
 */
ngx_int_t ngx_http_brix_dashboard_page_handler(ngx_http_request_t *r);

/*
 * Config-download route (GET/HEAD /xrootd/api/v1/config). Serves the running
 * nginx config (ngx_cycle->conf_file) as a text/plain attachment with ALL
 * secrets redacted by a fail-closed filter (values are masked unless the
 * directive is on a curated safe allowlist; `include` targets are not inlined).
 * ALWAYS requires auth — never served anonymously even when brix_dashboard_
 * anonymous is on. Returns the auth-failure code, NGX_HTTP_NOT_ALLOWED for
 * non-GET/HEAD, a 5xx with no body on read failure, or the output-filter result.
 */
ngx_int_t ngx_http_brix_dashboard_config_download_handler(
    ngx_http_request_t *r);

/*
 * Login route: GET/HEAD serves the login form; POST reads the body
 * asynchronously and verifies credentials in a body callback, so the POST
 * path returns NGX_DONE (response finalized later by the callback).
 * Returns NGX_HTTP_NOT_ALLOWED for other methods, or the form send result.
 */
ngx_int_t ngx_http_brix_dashboard_login_handler(ngx_http_request_t *r);

/*
 * Validate the request's xrd_dashboard cookie (HMAC + timestamp, optional
 * username field in multi-user mode); conf is borrowed, not retained.
 * Fails closed: any missing/malformed/expired/forged cookie yields
 * NGX_HTTP_UNAUTHORIZED and appends a dashboard AUTH audit event as a side
 * effect. Returns NGX_OK when valid OR when no password/users are configured
 * (dashboard is then open and the cookie is not inspected).
 */
ngx_int_t ngx_http_brix_dashboard_check_auth(ngx_http_request_t *r,
    const ngx_http_brix_dashboard_loc_conf_t *conf,
    ngx_uint_t suppress_missing_cookie);

#endif /* BRIX_DASHBOARD_HTTP_H */
