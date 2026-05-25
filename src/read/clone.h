#ifndef XROOTD_CLONE_H
#define XROOTD_CLONE_H
/*
 * kXR_clone (3032) — server-side range copy.

 * Exported:
 *   xrootd_handle_clone() — Implements the clone opcode: parses a batch of
 *     clone_item structures from the payload, validates dst_fhandle for write
 *     access and each src_fhandle for read access, then copies each specified
 *     byte range via xrootd_copy_range(). Accumulates total_bytes into file
 *     and session counters.

 * See also: src/read/clone.c (full implementation), src/read/README.md (read module overview).
 */

#include "../ngx_xrootd_module.h"

ngx_int_t xrootd_handle_clone(xrootd_ctx_t *ctx, ngx_connection_t *c);

#endif /* XROOTD_CLONE_H */
