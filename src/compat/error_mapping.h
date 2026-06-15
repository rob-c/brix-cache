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
#include "../protocol/opcodes.h"

/*
 * Sections 1-2 are ngx-free (pure uint16_t/int) and compile into the standalone
 * libxrdproto core. Section 3 returns ngx_int_t for NGX_HTTP_* comparisons and is
 * module-only. When building libxrdproto (-DXRDPROTO_NO_NGX) we pull only the
 * ngx-free enum (ns_status.h) and omit Section 3; the module build pulls the full
 * namespace_ops.h (which provides ngx_int_t transitively) exactly as before.
 */
#ifdef XRDPROTO_NO_NGX
#include "ns_status.h"
#else
#include "namespace_ops.h"
#endif

/* Section 1: errno → kXR */
uint16_t xrootd_kxr_from_errno(int err);
uint16_t xrootd_kxr_map_ns_status(xrootd_ns_status_t status, int sys_errno);

/* Section 2: errno → HTTP status codes (plain integer) */
int xrootd_http_errno_to_status(int err);

#ifndef XRDPROTO_NO_NGX
/* Section 3: namespace status → HTTP (ngx_int_t for NGX_HTTP_* comparison) */
ngx_int_t xrootd_http_map_ns_status(xrootd_ns_status_t status);
ngx_int_t xrootd_http_map_errno(int err);
#endif

#endif /* XROOTD_COMPAT_ERROR_MAPPING_H */
