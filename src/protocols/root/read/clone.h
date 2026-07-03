#ifndef BRIX_CLONE_H
#define BRIX_CLONE_H
/*
 * kXR_clone (3032) — server-side range copy.

 * Exported:
 *   brix_handle_clone() — Implements the clone opcode: parses a batch of
 *     clone_item structures from the payload, validates dst_fhandle for write
 *     access and each src_fhandle for read access, then copies each specified
 *     byte range via brix_copy_range(). Accumulates total_bytes into file
 *     and session counters.

 * See also: src/read/clone.c (full implementation), src/read/README.md (read module overview).
 */

#include "core/ngx_brix_module.h"

ngx_int_t brix_handle_clone(brix_ctx_t *ctx, ngx_connection_t *c);

#endif /* BRIX_CLONE_H */
