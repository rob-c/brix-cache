#ifndef BRIX_CORE_HTTP_BODY_INTERNAL_H
#define BRIX_CORE_HTTP_BODY_INTERNAL_H

/*
 * http_body_internal.h - private cross-file helper contract for the http_body
 * translation units.
 *
 * WHAT: Declares the one request-body helper that is defined in http_body.c but
 *       also called from the sibling decode translation unit
 *       (http_body_decode.c): brix_http_body_pwrite_full, the EINTR/short-write
 *       drain of a memory buffer into a destination fd.
 *
 * WHY:  http_body.c was split by concern (raw chain read/write vs codec-based
 *       decompress-to-fd). The decode side reuses the exact same output-drain
 *       loop the write side uses, so the helper must be non-static and shared;
 *       it is intentionally kept out of the public http_body.h because no
 *       protocol handler calls it directly — only these two internal units do.
 *
 * HOW:  include-guarded declaration only; the definition (with its full
 *       WHAT/WHY/HOW block) stays in http_body.c. Requires ngx core types.
 *
 * Requires: <ngx_config.h>, <ngx_core.h> before inclusion.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * brix_http_body_pwrite_full - loop pwrite to drain a memory buffer into fd.
 *
 * WHAT: Writes data[0..len] into fd at position *off through the VFS
 *       pwrite-full primitive, advancing *off by len on success. Returns
 *       NGX_OK, or NGX_ERROR after logging a path-tagged failure.
 * WHY:  Memory-backed nginx buffers have no file fd, so both the plain write
 *       path and the codec-decode output path must push their bytes out with a
 *       pwrite drain; sharing one implementation keeps the two units identical.
 * HOW:  delegate the short-write/EINTR loop to brix_vfs_pwrite_full, log with
 *       the caller's path on failure, then advance the running offset.
 */
ngx_int_t brix_http_body_pwrite_full(ngx_log_t *log, ngx_fd_t fd,
    const u_char *data, size_t len, off_t *off, const char *path);

#endif /* BRIX_CORE_HTTP_BODY_INTERNAL_H */
