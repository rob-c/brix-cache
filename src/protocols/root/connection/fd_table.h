#ifndef XROOTD_CONN_FD_H
#define XROOTD_CONN_FD_H

#include "core/ngx_xrootd_module.h"

/*
 * XRootD file-handle table for a single TCP session.
 *
 * The XRootD wire protocol uses a 4-byte opaque "fhandle" to refer to an
 * open file across multiple requests (kXR_read, kXR_write, kXR_close, etc.).
 * Internally we map the client-chosen fhandle byte to a slot index in
 * ctx->files[XROOTD_MAX_FILES].
 *
 * IMPORTANT — fhandle scope: primary fhandles are owned by the TCP session
 * that issued kXR_open.  kXR_bind secondaries may read those handles only
 * while the primary continues publishing the matching slot in shared memory;
 * they may not open, close, or write their own file handles.
 *
 * Slot lifecycle:
 *   alloc  → xrootd_alloc_fhandle   (returns slot index, sets fd = -1)
 *   open   → caller sets ctx->files[idx].fd and other fields
 *   use    → xrootd_validate_{file,read,write}_handle before each I/O
 *   close  → xrootd_free_fhandle    (closes fd, frees path, clears slot)
 *   cleanup→ xrootd_close_all_files (called on disconnect)
 */

/*
 * xrootd_alloc_fhandle — find the first free slot in ctx->files[].
 *
 * Returns: slot index [0, XROOTD_MAX_FILES) on success, -1 if table full.
 */
int xrootd_alloc_fhandle(xrootd_ctx_t *ctx);

/*
 * xrootd_set_fhandle_path — store the canonical filesystem path for a slot.
 *
 * The path is heap-allocated (ngx_alloc / ngx_free) so it can outlive the
 * request pool.  The previous path, if any, is freed.
 *
 * Returns: NGX_OK on success, NGX_ERROR on invalid arguments or OOM.
 */
ngx_int_t xrootd_set_fhandle_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *path);

/*
 * xrootd_free_fhandle — close the fd and release all resources for a slot.
 *
 * Clears all fields in ctx->files[handle_index].  If a checkpoint file
 * exists (ckp_path), it is unlinked to abandon any uncommitted transaction.
 * Safe to call on an already-free slot (fd == -1).
 */
void xrootd_free_fhandle(xrootd_ctx_t *ctx, int handle_index);

/*
 * xrootd_close_all_files — close and free every slot in the handle table.
 *
 * Called on TCP disconnect via xrootd_on_disconnect().  After this call the
 * table is empty and all kernel fds are closed.
 */
void xrootd_close_all_files(xrootd_ctx_t *ctx);

/*
 * xrootd_ctx_has_open_file — 1 if any handle slot is occupied (fd >= 0), else 0.
 *
 * A connection holding an open file is mid-transfer (e.g. a streaming read parked
 * between kXR_read chunks). The recv-loop drain gate uses this so a worker draining
 * after a reload lets such a connection finish on the old worker instead of a
 * fast-teardown that forces a fragile mid-stream reconnect.
 */
int xrootd_ctx_has_open_file(const xrootd_ctx_t *ctx);

/*
 * xrootd_ensure_read_handle — prepare a handle for read-side I/O.
 *
 * For primary connections this is just a local table check.  For kXR_bind
 * secondaries it may lazily reopen the primary's published handle in this
 * worker, because raw fd integers cannot be shared safely across workers.
 *
 * Returns NGX_OK when ctx->files[handle_index] is ready for reading,
 * NGX_DECLINED when no readable handle is available, NGX_ERROR on local
 * resource failure.
 */
ngx_int_t xrootd_ensure_read_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index);

/*
 * xrootd_validate_file_handle — verify that handle_index refers to an open
 * file.  On failure, sends kXR_FileNotOpen and writes the error rc to *rc.
 *
 * Returns: 1 (valid), 0 (invalid — error response already queued).
 */
ngx_flag_t xrootd_validate_file_handle(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int handle_index, const char *verb, ngx_uint_t op,
    ngx_int_t *rc);

/*
 * xrootd_validate_read_handle — validate handle and check readable flag.
 * Returns: 1 if handle is open and readable, 0 otherwise.
 */
ngx_flag_t xrootd_validate_read_handle(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int handle_index, const char *verb,
    ngx_uint_t op, ngx_int_t *rc);

/*
 * xrootd_validate_write_handle — validate handle and check writable flag.
 * Returns: 1 if handle is open and writable, 0 otherwise.
 */
ngx_flag_t xrootd_validate_write_handle(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int handle_index, const char *verb,
    ngx_uint_t op, ngx_int_t *rc);

#endif /* XROOTD_CONN_FD_H */
