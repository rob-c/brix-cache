#ifndef XROOTD_RESULT_MAPPER_H
#define XROOTD_RESULT_MAPPER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "namespace_ops.h"

/*
 * xrootd_http_map_ns_status — map a namespace service status to HTTP.
 */
ngx_int_t xrootd_http_map_ns_status(xrootd_ns_status_t status);

/*
 * xrootd_http_map_errno — map a system errno to HTTP.
 * Thin wrapper over xrootd_http_errno_to_status() that returns ngx_int_t.
 */
ngx_int_t xrootd_http_map_errno(int err);

#endif /* XROOTD_RESULT_MAPPER_H */
