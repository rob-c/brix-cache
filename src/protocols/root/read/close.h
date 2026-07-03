#ifndef BRIX_CLOSE_H
#define BRIX_CLOSE_H
/*
 * kXR_close (3016) — file handle lifecycle termination.

 * Exported:
 *   brix_handle_close() — Implements the close opcode: validates the handle,
 *     logs throughput metrics before freeing fields, performs POSC atomic rename
 *     if staging is active, flushes write-through dirty data to origin (sync or
 *     async), frees all resources via brix_free_fhandle(), and returns kXR_ok.

 * See also: src/read/close.c (full implementation), src/read/README.md (read module overview).
 */

#include "core/ngx_brix_module.h"

ngx_int_t brix_handle_close(brix_ctx_t *ctx, ngx_connection_t *c);

#endif // BRIX_CLOSE_H
