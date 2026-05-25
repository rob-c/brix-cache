#ifndef XROOTD_READ_OPEN_H
#define XROOTD_READ_OPEN_H
/*
 * kXR_open (3012) — file handle lifecycle initiation.

 * Exported:
 *   xrootd_handle_open()       — Implements the open opcode: parses ClientOpenRequest
 *     from wire, resolves path via xrootd_resolve_path(), checks VO ACL and token scope,
 *     detects write-mode vs read-mode, opens file with appropriate flags, allocates fhandle
 *     slot in fd_table.c, returns retstat body.

 *   xrootd_open_resolved_file() — Opens a pre-resolved path: allocates fhandle via
 *     xrootd_alloc_fhandle(), open(2) with write-mode detection and TPC flag check,
 *     sends retstat response. Flags=0 for cache reads, flags=1 for write opens.

 *   xrootd_open_cached_read()  — Cache-aware read-open: resolves against auth root for ACL
 *     check, then tries cache root (hit → direct serve) or triggers background origin fill
 *     on miss via xrootd_cache_open_or_fill(). Implements XCache-style caching.

 * See also: src/read/open.c (full implementation), src/read/README.md (read module overview).
 */

#include "../ngx_xrootd_module.h"

ngx_int_t xrootd_handle_open(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_open_resolved_file(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf, const char *resolved, uint16_t options, uint16_t mode_bits, ngx_flag_t is_write);
ngx_int_t xrootd_open_cached_read(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path, uint16_t options, uint16_t mode_bits);

#endif // XROOTD_READ_OPEN_H
