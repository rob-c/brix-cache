/*
 * dashboard_json.h — shared JSON response serialiser for the dashboard HTTP
 * endpoints (read-only API, admin API, file browser).
 *
 * These handlers previously each carried a byte-identical send-json helper
 * (dashboard_send_json / admin_send_json / dashboard_files_send_json). They now
 * share this one, declared here so no handler depends on another's TU.
 */
#ifndef XROOTD_DASHBOARD_DASHBOARD_JSON_H
#define XROOTD_DASHBOARD_DASHBOARD_JSON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>

/*
 * Serialise `root` as a no-store application/json response with the given
 * status. Takes ownership of root (decref'd here — the caller must not touch it
 * afterwards), sizing the buffer to the payload via a two-pass json_dumpb.
 * Returns the ngx_http_output_filter result, or NGX_HTTP_INTERNAL_SERVER_ERROR
 * on a NULL/failed dump or allocation failure.
 */
ngx_int_t dashboard_json_send(ngx_http_request_t *r, ngx_int_t status,
    json_t *root);

#endif /* XROOTD_DASHBOARD_DASHBOARD_JSON_H */
