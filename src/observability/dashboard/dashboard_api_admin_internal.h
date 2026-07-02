/*
 * dashboard_api_admin_internal.h - private split contract for api_admin.c and its Phase-38 siblings.
 * Not a public API: include only from src/dashboard/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_DASHBOARD_API_ADMIN_INTERNAL_H
#define XROOTD_DASHBOARD_API_ADMIN_INTERNAL_H

#include "dashboard.h"
#include "api_admin.h"
#include "dashboard_json.h"
#include "net/manager/registry.h"
#include "webdav/proxy_pool.h"
#include "core/compat/http_headers.h"
#include <jansson.h>
#include <openssl/crypto.h>   
#define ADMIN_PREFIX      "/xrootd/api/v1/admin/"
#define ADMIN_MAX_BODY    65536
#define ADMIN_SECRET_MAX  4096
#define ADMIN_SECRET_MIN  16     
ngx_int_t xrootd_uring_killswitch_set(ngx_uint_t disabled);
ngx_int_t xrootd_uring_killswitch_get(void);
ngx_int_t xrootd_uring_admin_enabled(void);

typedef enum {
    XROOTD_ADMIN_AUTH_OK = 0,
    XROOTD_ADMIN_AUTH_DENIED,
} xrootd_admin_auth_result_t;

typedef ngx_int_t (*xrootd_admin_body_handler_t)(ngx_http_request_t *r,
    json_t *body);

typedef struct {
    xrootd_admin_body_handler_t  handler;
} xrootd_admin_body_ctx_t;


/* api_admin.c */
ngx_int_t admin_send_ok(ngx_http_request_t *r, const char *result);
ngx_int_t admin_send_error(ngx_http_request_t *r, ngx_int_t status, const char *code);
int admin_validate_hostname(const char *host);
int admin_validate_paths(const char *paths);
xrootd_admin_auth_result_t xrootd_admin_check_auth(ngx_http_request_t *r, const ngx_http_xrootd_dashboard_loc_conf_t *conf);
void admin_audit(ngx_http_request_t *r, const char *action, const char *target, const char *result);
void xrootd_admin_body_callback(ngx_http_request_t *r);
ngx_int_t xrootd_admin_read_body(ngx_http_request_t *r, xrootd_admin_body_handler_t handler);

/* api_admin_cluster.c */
ngx_int_t admin_parse_server_uri(ngx_http_request_t *r, char *host_out, size_t host_size, uint16_t *port_out, char *action_out, size_t action_size);
ngx_int_t admin_cluster_register(ngx_http_request_t *r, json_t *body);
ngx_int_t admin_cluster_drain(ngx_http_request_t *r, json_t *body);
ngx_int_t admin_cluster_delete(ngx_http_request_t *r);
ngx_int_t admin_cluster_undrain(ngx_http_request_t *r);

/* api_admin.c */
int admin_validate_url(const char *url);

/* api_admin_proxy.c */
ngx_int_t admin_parse_proxy_uri(ngx_http_request_t *r, uint32_t *id_out, char *action_out, size_t action_size);
json_t * admin_proxy_backend_json(const xrootd_proxy_be_snapshot_t *e);
int admin_url_host_allowed(ngx_http_xrootd_dashboard_loc_conf_t *conf, const char *url);
ngx_int_t admin_proxy_add(ngx_http_request_t *r, json_t *body);
ngx_int_t admin_proxy_list(ngx_http_request_t *r);
ngx_int_t admin_proxy_one(ngx_http_request_t *r, const char *action, uint32_t id);

/* api_admin.c */
int admin_uri_eq(ngx_http_request_t *r, const char *s);
int admin_uri_has_action(ngx_http_request_t *r, const char *action);

/* api_admin_config.c */
ngx_int_t admin_io_uring_set(ngx_http_request_t *r, json_t *body);
ngx_int_t admin_io_uring_get(ngx_http_request_t *r);

#endif /* XROOTD_DASHBOARD_API_ADMIN_INTERNAL_H */
