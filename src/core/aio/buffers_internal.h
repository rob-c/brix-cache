/*
 * buffers_internal.h — declarations shared across the response-chain builder
 * files after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the three low-level chain-assembly helpers that live in
 *       buffers.c but are also called by the sendfile builders in
 *       buffers_sendfile.c.
 * WHY:  buffers.c (863 lines) split into three focused files under the 500-line
 *       cap: buffers.c (shared helpers + memory-chain builders),
 *       buffers_sendfile.c (sendfile-chain builders + pgread chain), and
 *       buffers_scratch.c (pool/scratch buffer lifecycle). The multi-chunk
 *       sendfile builder reuses the same chunk-geometry math and the same
 *       memory/file link-append helpers as the memory path, so exactly those
 *       three helpers become non-static and are declared here — nothing else
 *       crosses the boundary.
 * HOW:  Both buffers.c and buffers_sendfile.c include this header; none of the
 *       symbols is exported beyond the aio response-builder unit.
 *
 * Requires: core/ngx_brix_module.h (brix_ctx_t, ngx_pool_t, ngx_chain_t,
 *           ngx_connection_t) included before this header.
 */
#ifndef BRIX_CORE_AIO_BUFFERS_INTERNAL_H
#define BRIX_CORE_AIO_BUFFERS_INTERNAL_H

#include "core/ngx_brix_module.h"

/* Defined in buffers.c. Computes the wire-frame count and final-frame size for
 * a multi-chunk read (shared by the memory and sendfile builders). */
void brix_chunk_geometry(size_t data_total, size_t *n_chunks_out,
    size_t *last_size_out);

/* Defined in buffers.c. Allocates and appends a memory-backed buffer link
 * spanning [pos, last) to a head/tail-tracked chain. Returns NGX_OK/NGX_ERROR. */
ngx_int_t brix_chain_append_mem(ngx_pool_t *pool, ngx_chain_t **head,
    ngx_chain_t **tail, u_char *pos, u_char *last);

/* Defined in buffers.c. Allocates and appends a file-backed (sendfile) buffer
 * link covering fd bytes [file_pos, file_last). Returns NGX_OK/NGX_ERROR. */
ngx_int_t brix_chain_append_file(ngx_pool_t *pool, ngx_connection_t *c,
    ngx_chain_t **head, ngx_chain_t **tail, int fd, const char *path,
    off_t file_pos, off_t file_last);

#endif /* BRIX_CORE_AIO_BUFFERS_INTERNAL_H */
