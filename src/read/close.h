#ifndef XROOTD_CLOSE_H
#define XROOTD_CLOSE_H
/*
 * kXR_close (3016) — file handle lifecycle termination.

 * Exported:
 *   xrootd_handle_close() — Implements the close opcode: validates the handle,
 *     logs throughput metrics before freeing fields, performs POSC atomic rename
 *     if staging is active, flushes write-through dirty data to origin (sync or
 *     async), frees all resources via xrootd_free_fhandle(), and returns kXR_ok.

 * See also: src/read/close.c (full implementation), src/read/README.md (read module overview).
 */

#include "ngx_xrootd_module.h"

ngx_int_t xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c);

#endif // XROOTD_CLOSE_H
