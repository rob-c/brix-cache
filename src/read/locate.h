#ifndef XROOTD_READ_LOCATE_H
#define XROOTD_READ_LOCATE_H
/*
 * kXR_locate (3014) — endpoint location query for distributed HEP storage.

 * Exported:
 *   xrootd_handle_locate() — Implements the locate opcode: parses path from
 *     payload, then routes through three modes: dynamic registry query via CMS
 *     parent with pending timeout tracking (manager_mode), static map prefix-based
 *     redirect (manager_map configured), or wildcard global enumeration ('*').
 *     Returns kXR_ok with host:port redirect body or kXR_Overloaded error.

 * See also: src/read/locate.c (full implementation), src/read/README.md (read module overview).
 */

#include "core/ngx_xrootd_module.h"

ngx_int_t xrootd_handle_locate(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif

