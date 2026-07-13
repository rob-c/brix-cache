#ifndef BRIX_READ_H
#define BRIX_READ_H

/* ---- Module: Read Operations ----
 *
 * WHAT: Function declarations for XRootD read-side opcodes — kXR_read (single-segment raw byte stream),
 *       kXR_readv (multi-segment scatter-gather), kXR_pgread (page-mode with per-page CRC32c integrity).
 *       brix_pgread_encode_pages() provides the shared page/CRC trailer encoding used by pgread.
 *
 * WHY: These opcodes form the data-transfer core of XRootD — clients use read for simple byte-stream
 *      delivery, readv for scatter-gather access patterns, and pgread for integrity-verified large-file
 *      transfers. Each function validates its handle or path, performs pread(2), builds response chain,
 *      and queues to the client event loop.
 */

#include "core/ngx_brix_module.h"
#include "fs/backend/sd.h"   /* brix_sd_obj_t — pgread routes via the SD seam */

/* ---- Function: brix_handle_read() ----
 * Handles kXR_read opcode — single-segment file read returning raw bytes to client.
 * Validates read handle (idx from fhandle[0]), parses offset/rlen, caps rlen at BRIX_READ_REQUEST_MAX,
 * performs pread(2) via AIO thread-pool or inline fallback, builds response chain and queues it.
 */
ngx_int_t brix_handle_read(brix_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: brix_read_compressed() ----
 * Phase-42 W4 — inline read-compression path for kXR_read.  Invoked from
 * brix_handle_read() ONLY when ctx->files[idx].read_codec != IDENTITY (an
 * opt-in handle opened with "?xrootd.compress=").  Synchronously reads a bounded
 * plaintext window, compresses it as one self-contained codec frame, and queues
 * the compressed bytes as a single kXR_read response (the client inflates).
 * pgread/readv never reach here, preserving their plaintext + CRC32c invariant.
 * `offset`/`rlen` are the already-parsed, already-clamped request fields.
 */
ngx_int_t brix_read_compressed(brix_ctx_t *ctx, ngx_connection_t *c,
                                 ngx_stream_brix_srv_conf_t *rconf,
                                 int idx, off_t offset, size_t rlen);

/* ---- Function: brix_handle_readv() ----
 * Handles kXR_readv opcode — multi-segment scatter-gather read returning interleaved data chunks.
 * Validates segment list (count <= BRIX_READV_MAX_SEGS), validates each handle, caps per-segment rlen,
 * performs pread(2) on each segment via AIO thread-pool or inline fallback, assembles response chain.
 */
ngx_int_t brix_handle_readv(brix_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: brix_handle_pgread() ----
 * Handles kXR_pgread opcode — page-mode read returning raw bytes interleaved with per-page CRC32c checksums.
 * Validates handle, parses offset/rlen, divides into pages (BRIX_READ_PAGE_SIZE), performs pread(2)
 * on each page via AIO thread-pool or inline fallback, encodes kXR_status framing + per-page CRC,
 * builds response chain and queues it. Integrity-verified transfer for large-file downloads.
 */
ngx_int_t brix_handle_pgread(brix_ctx_t *ctx, ngx_connection_t *c);

/* ---- Function: brix_pgread_encode_pages() ----
 * Encodes page-mode response data — interleaves kXR_status trailer + per-page CRC32c checksums into dst buffer.
 * Input src contains raw file bytes read from `offset`; output dst contains byte-stream with CRC32c appended after each page.
 * `offset` is the absolute file offset of src[0]: pages are aligned to it (short first page when unaligned) so every
 * later page begins on a kXR_pgPageSZ multiple, matching official XRootD and the pgRetry/AsyncPageReader contract.
 * Returns encoded length (src_len + page_count * sizeof(kXR_pageStatus)). Shared encoding used by pgread.
 */
size_t brix_pgread_encode_pages(const u_char *src, size_t len, off_t offset,
                                  u_char *dst);

/* ---- Struct: brix_pgread_io_t ----
 * In/out I/O exchange for brix_pgread_read_encode_inplace. `nowait` is the
 * single input (read mode); `nread`/`io_errno` are the outputs describing what
 * the read actually delivered. Zero-initialize before the call.
 */
typedef struct {
    int      nowait;     /* in: 1 = preadv2(RWF_NOWAIT) warm-cache probe, 0 = blocking read */
    ssize_t  nread;      /* out: bytes read; -1 on I/O error */
    int      io_errno;   /* out: errno on error; EAGAIN on a nowait miss */
} brix_pgread_io_t;

/* ---- Function: brix_pgread_read_encode_inplace() ----
 * Zero-copy paged read: reads file data DIRECTLY into the final kXR page-mode
 * wire buffer `out` ([CRC32c(4)][data] per page, file-offset aligned) via batched
 * preadv and computes each page CRC32c in place — no flat-buffer copy. `out` must
 * hold rlen + ceil-pages * 4 bytes. Returns encoded byte count; sets io->nread to
 * bytes read (-1 on I/O error, io->io_errno = errno). Output is byte-identical to
 * brix_pgread_encode_pages over the same bytes. Safe to call on a worker thread
 * (pure I/O + CRC; touches no ctx/connection/pool).
 *
 * When io->nowait is set the batched reads use preadv2(RWF_NOWAIT): if the whole
 * range is NOT page-cache resident (any short batch or EAGAIN) the call aborts
 * early with io->nread=0 and io->io_errno=EAGAIN, having produced nothing
 * usable — the caller must treat that as a miss and fall back to a blocking
 * read. A clean hit returns the full encoding with io->nread==rlen. This powers
 * the event-loop warm-cache fast path (skip the thread-pool offload when the
 * data is resident); leave nowait 0 for the normal blocking read.
 */
size_t brix_pgread_read_encode_inplace(brix_sd_obj_t *obj, off_t offset,
                                         size_t rlen, u_char *out,
                                         brix_pgread_io_t *io);

#endif // BRIX_READ_H
