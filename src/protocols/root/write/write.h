#ifndef BRIX_WRITE_H
#define BRIX_WRITE_H

#include "core/ngx_brix_module.h"
#include "core/compat/pgio.h"   /* xrdp_pg_bad_t */

/* kXR_write — write bytes from payload to an open file at a given offset. */
ngx_int_t brix_handle_write(brix_ctx_t *ctx, ngx_connection_t *c);

/* Phase-42 W5 — inline write decompression for kXR_write.  Invoked from
 * brix_handle_write() ONLY when ctx->files[idx].write_codec != IDENTITY (an
 * opt-in handle opened for write with "?xrootd.compress=").  Decompresses the
 * payload — a self-contained codec frame — under a bomb guard and streams the
 * plaintext to pwrite at `offset`.  pgwrite never reaches here (stays plaintext).
 * `offset` is the PLAINTEXT file offset; `wlen` is the compressed payload length. */
ngx_int_t brix_write_compressed(brix_ctx_t *ctx, ngx_connection_t *c,
                                  int idx, int64_t offset, size_t wlen);

/* Whole-object staged-commit adapter (phase-70) — append one kXR_write/pgwrite
 * block to the handle's VFS staged handle at the running sequential offset, then
 * reply. Invoked ONLY when ctx->files[idx].staged != NULL (a write open that
 * resolved to a backend LEAF with no random write, e.g. sd_http). Enforces
 * sequential append: an out-of-order offset is refused with kXR_Unsupported
 * (random-offset write to a whole-object backend is unsupported). `flat`/`flen`
 * carry the already-decoded plaintext bytes for pgwrite; a plain kXR_write passes
 * flat=NULL and the recv payload is used. */
ngx_int_t brix_write_staged(brix_ctx_t *ctx, ngx_connection_t *c,
                              int idx, int64_t offset, size_t wlen);
ngx_int_t brix_write_staged_buf(brix_ctx_t *ctx, ngx_connection_t *c,
                                  int idx, int64_t offset,
                                  const u_char *buf, size_t len);
/* Append core WITHOUT a success reply — the pgwrite path appends then sends its
 * own kXR_status frame. On any failure the error reply is sent and *rc holds it;
 * returns NGX_ERROR then (caller returns *rc), else NGX_OK (append done). */
ngx_int_t brix_staged_append(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
                               int64_t offset, const u_char *buf, size_t len,
                               ngx_int_t *rc);

/* Commit the handle's staged whole object (single backend PUT) — the kXR_sync /
 * kXR_close hook for a staged write handle. Idempotent: a second call after a
 * successful commit is a no-op success (sync-then-close). On commit failure sets
 * *err_out to errno and returns NGX_ERROR (caller maps to kXR_IOError); the
 * staged handle is left intact so no partial object is published. Returns NGX_OK
 * on success (or nothing-to-commit) with staged_committed set. */
ngx_int_t brix_staged_commit_handle(brix_ctx_t *ctx, int idx, int *err_out);

/* kXR_pgwrite — page-aligned write with per-4096-byte CRC validation. */
ngx_int_t brix_handle_pgwrite(brix_ctx_t *ctx, ngx_connection_t *c);

/* kXR_writev — multi-segment scatter write, one pwrite per segment. */
ngx_int_t brix_handle_writev(brix_ctx_t *ctx, ngx_connection_t *c);

/* kXR_writev stock framing helper — validate the dlen-framed write_list
 * descriptor block and report sum(wlen), the segment-data byte count the
 * client streams AFTER the request frame.  Used by the recv framing to extend
 * the read obligation before dispatch.  NGX_OK + *extra, or NGX_DECLINED on a
 * contract violation (caller chooses the error). */
ngx_int_t brix_writev_body_extra(const u_char *desc, uint32_t dlen,
    uint32_t *extra);

/* kXR_chkpoint/kXR_ckpXeq stock framing helper — the outer frame's dlen
 * covers ONLY the embedded 24-byte sub-request header; the sub-request body
 * streams after it (and, for an embedded kXR_writev, the segment data streams
 * after the descriptor block).  Called by the recv framing each time the
 * current read obligation completes: `have` is the body byte count received
 * so far (24 = embedded header just landed; 24 + sub_dlen = embedded writev
 * descriptors landed).  NGX_OK + *extra (bytes still to stream) + *final
 * (0 = call again after the extension completes), or NGX_DECLINED when the
 * embedded request violates the contract — no extension; the handler emits
 * the error and drops the link.  Defined in chkpoint_xeq.c. */
ngx_int_t brix_ckpxeq_body_extra(const u_char *body, uint32_t have,
    uint32_t *extra, unsigned *final);

/* kXR_sync — fsync(2) the file referenced by the handle. */
ngx_int_t brix_handle_sync(brix_ctx_t *ctx, ngx_connection_t *c);

/* kXR_truncate — ftruncate the path named in the payload. */
ngx_int_t brix_handle_truncate(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* kXR_mkdir — create a directory (with optional kXR_mkpth parent creation). */
ngx_int_t brix_handle_mkdir(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* kXR_rm — unlink a file. */
ngx_int_t brix_handle_rm(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* kXR_rmdir — remove an empty directory. */
ngx_int_t brix_handle_rmdir(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* kXR_mv — rename a file or directory. */
ngx_int_t brix_handle_mv(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* kXR_chmod — change the permission bits of a file or directory. */
ngx_int_t brix_handle_chmod(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_pgwrite_decode_payload — decode a kXR_pgwrite payload into a flat
 * data buffer by stripping the per-4096-byte CRC records.
 *
 * The pgwrite wire format interleaves data pages with 4-byte IEEE CRC32C
 * records:  [page0 (4096 bytes)][crc32c(4 bytes)][page1...][crc32c...]
 * Partial pages at the end have a proportional CRC.
 *
 * flat: caller-allocated output buffer of size >= payload_len.
 * flat_len: set to the number of decoded data bytes on success.
 * bad_offset: set to the file offset of the first CRC mismatch, or -1.
 *
 * Returns NGX_OK if all CRCs matched, NGX_ERROR on mismatch or malformed input.
 */
ngx_int_t brix_pgwrite_decode_payload(const u_char *payload,
    size_t payload_len, int64_t offset, u_char *flat, size_t *flat_len,
    int64_t *bad_offset);

/*
 * brix_try_post_write_aio — allocate an AIO write task and post it to the
 * thread pool.
 *
 * If no thread pool is configured (conf->common.thread_pool == NULL), returns NGX_OK
 * with *posted = 0 so the caller falls back to synchronous pwrite.
 *
 * payload_to_free: if non-NULL, this buffer is freed by the done callback
 *   after the write completes (used when the payload has been detached from
 *   ctx->recv.payload_buf).
 *
 * bad / bad_count: pgwrite CSE bad-page list (NULL/0 for plain kXR_write). When
 *   non-empty the done callback emits a CSE retransmit frame; the list is copied
 *   into the task so the caller's stack buffer need not outlive the post.
 *
 * Returns NGX_OK (task posted or not posted), NGX_ERROR on task alloc failure.
 */
ngx_int_t brix_try_post_write_aio(brix_ctx_t *ctx, ngx_connection_t *c,
    int idx, off_t offset, const u_char *data, size_t len,
    int64_t req_offset, ngx_uint_t is_pgwrite, u_char *payload_to_free,
    const xrdp_pg_bad_t *bad, size_t bad_count,
    const char *fallback_log, ngx_flag_t *posted);

#endif /* BRIX_WRITE_H */
