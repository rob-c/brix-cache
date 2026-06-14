#ifndef XROOTD_READ_H
#define XROOTD_READ_H

/* ---- Module: Read Operations ----
 *
 * WHAT: Function declarations for XRootD read-side opcodes — kXR_read (single-segment raw byte stream),
 *       kXR_readv (multi-segment scatter-gather), kXR_pgread (page-mode with per-page CRC32c integrity).
 *       xrootd_pgread_encode_pages() provides the shared page/CRC trailer encoding used by pgread.
 *
 * WHY: These opcodes form the data-transfer core of XRootD — clients use read for simple byte-stream
 *      delivery, readv for scatter-gather access patterns, and pgread for integrity-verified large-file
 *      transfers. Each function validates its handle or path, performs pread(2), builds response chain,
 *      and queues to the client event loop.
 */

#include "../ngx_xrootd_module.h"

/* ---- Function: xrootd_handle_read() ----
 * Handles kXR_read opcode — single-segment file read returning raw bytes to client.
 * Validates read handle (idx from fhandle[0]), parses offset/rlen, caps rlen at XROOTD_READ_REQUEST_MAX,
 * performs pread(2) via AIO thread-pool or inline fallback, builds response chain and queues it.
 */
ngx_int_t xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: xrootd_handle_readv() ----
 * Handles kXR_readv opcode — multi-segment scatter-gather read returning interleaved data chunks.
 * Validates segment list (count <= XROOTD_READV_MAX_SEGS), validates each handle, caps per-segment rlen,
 * performs pread(2) on each segment via AIO thread-pool or inline fallback, assembles response chain.
 */
ngx_int_t xrootd_handle_readv(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: xrootd_handle_pgread() ----
 * Handles kXR_pgread opcode — page-mode read returning raw bytes interleaved with per-page CRC32c checksums.
 * Validates handle, parses offset/rlen, divides into pages (XROOTD_READ_PAGE_SIZE), performs pread(2)
 * on each page via AIO thread-pool or inline fallback, encodes kXR_status framing + per-page CRC,
 * builds response chain and queues it. Integrity-verified transfer for large-file downloads.
 */
ngx_int_t xrootd_handle_pgread(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: xrootd_pgread_encode_pages() ----
 * Encodes page-mode response data — interleaves kXR_status trailer + per-page CRC32c checksums into dst buffer.
 * Input src contains raw file bytes read from `offset`; output dst contains byte-stream with CRC32c appended after each page.
 * `offset` is the absolute file offset of src[0]: pages are aligned to it (short first page when unaligned) so every
 * later page begins on a kXR_pgPageSZ multiple, matching official XRootD and the pgRetry/AsyncPageReader contract.
 * Returns encoded length (src_len + page_count * sizeof(kXR_pageStatus)). Shared encoding used by pgread.
 */
size_t xrootd_pgread_encode_pages(const u_char *src, size_t len, off_t offset,
                                  u_char *dst);

#endif // XROOTD_READ_H
