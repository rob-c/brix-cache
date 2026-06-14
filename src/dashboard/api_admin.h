/*
 * api_admin.h — Phase 23 REST admin write API for the dashboard module.
 *
 * Exposes /xrootd/api/v1/admin/ endpoints that mutate runtime state:
 *   - cluster/servers      register / delete / drain / undrain data servers
 *   - proxy/backends       add / delete / drain / undrain WebDAV proxy backends
 *
 * Every write is guarded by xrootd_admin_check_auth() (CIDR allowlist and/or a
 * bearer secret), validated against a strict whitelist before touching shared
 * memory, and audit-logged.  The API is disabled (403) unless at least one of
 * xrootd_admin_allow / xrootd_admin_secret is configured.
 */
#ifndef XROOTD_DASHBOARD_API_ADMIN_H
#define XROOTD_DASHBOARD_API_ADMIN_H

#include "dashboard_http.h"

/*
 * Route, authenticate, and dispatch an /xrootd/api/v1/admin/ request.
 * Returns an HTTP status code, or NGX_DONE when an async body read is in
 * flight (the body callback finalizes the request).
 */
ngx_int_t xrootd_admin_dispatch(ngx_http_request_t *r);

/* Directive setters (registered in dashboard/module.c command table). */
char *xrootd_admin_set_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *xrootd_admin_set_secret(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *xrootd_admin_set_proxy_allow(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* XROOTD_DASHBOARD_API_ADMIN_H */
