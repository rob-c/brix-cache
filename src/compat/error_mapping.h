/*
 * error_mapping.h — unified errno → protocol status mapping.
 *
 * Consolidates three domains previously split across kxr_errno.h, http_errno.h,
 * and result_mapper.h:
 *   1. POSIX errno → XRootD kXR codes (xrootd_kxr_from_errno)
 *   2. POSIX errno → HTTP status codes (xrootd_http_errno_to_status)
 *   3. Namespace service status → HTTP (xrootd_http_map_ns_status, xrootd_http_map_errno)
 */

#ifndef XROOTD_COMPAT_ERROR_MAPPING_H
#define XROOTD_COMPAT_ERROR_MAPPING_H

#include <stdint.h>
#include "namespace_ops.h"
#include "../protocol/opcodes.h"

/* Section 1: errno → kXR */
uint16_t xrootd_kxr_from_errno(int err);
uint16_t xrootd_kxr_map_ns_status(xrootd_ns_status_t status, int sys_errno);

/* Section 2: errno → HTTP status codes (plain integer) */
int xrootd_http_errno_to_status(int err);

/* Section 3: namespace status → HTTP (ngx_int_t for NGX_HTTP_* comparison) */
ngx_int_t xrootd_http_map_ns_status(xrootd_ns_status_t status);
ngx_int_t xrootd_http_map_errno(int err);

#endif /* XROOTD_COMPAT_ERROR_MAPPING_H */
