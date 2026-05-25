#ifndef XROOTD_DASHBOARD_TRACKING_H
#define XROOTD_DASHBOARD_TRACKING_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "dashboard.h"

int xrootd_dashboard_http_start(ngx_http_request_t *r, const char *path,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes);

int xrootd_dashboard_http_start_identity(ngx_http_request_t *r,
    const char *path, const char *identity, const char *vo,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes);

void xrootd_dashboard_http_add(ngx_http_request_t *r,
    ngx_atomic_int_t bytes);
void xrootd_dashboard_http_state(ngx_http_request_t *r, uint8_t state);
void xrootd_dashboard_http_error(ngx_http_request_t *r, const char *reason);
void xrootd_dashboard_http_tpc_remote(ngx_http_request_t *r,
    const char *remote_url, int remote_status, int curl_exit);
void xrootd_dashboard_http_finish(ngx_http_request_t *r);

#endif /* XROOTD_DASHBOARD_TRACKING_H */
