#ifndef BRIX_RESULT_MAPPER_H
#define BRIX_RESULT_MAPPER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "namespace_ops.h"

/*
 * brix_http_map_ns_status — map a namespace service status to HTTP.
 */
ngx_int_t brix_http_map_ns_status(brix_ns_status_t status);

/*
 * brix_http_map_errno — map a system errno to HTTP.
 * Thin wrapper over brix_http_errno_to_status() that returns ngx_int_t.
 */
ngx_int_t brix_http_map_errno(int err);

#endif /* BRIX_RESULT_MAPPER_H */
