#ifndef BRIX_CORE_HTTP_SESSLOG_CONN_H
#define BRIX_CORE_HTTP_SESSLOG_CONN_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "core/config/shared_conf.h"
#include "observability/sesslog/sesslog_ngx.h"

/*
 * WHAT: Acquire the connection-scoped sesslog session for an HTTP request.
 * WHY: WebDAV, S3, and CVMFS share the same HTTP keepalive lifecycle: one SESS
 * ID per TCP connection, with request-level ATTEMPT/RESULT events.
 * HOW: A fixed per-worker registry keys records by ngx_connection_t*, and a
 * connection-pool cleanup emits END when nginx tears the connection down.
 */
brix_sess_t *brix_http_sess(ngx_http_request_t *r,
    const ngx_http_brix_shared_conf_t *conf, brix_sess_proto_t proto,
    brix_sess_am_t am);

const char *brix_http_sess_uri(ngx_http_request_t *r, char *dst,
    size_t dst_size);

#endif /* BRIX_CORE_HTTP_SESSLOG_CONN_H */
