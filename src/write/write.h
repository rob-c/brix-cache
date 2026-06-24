#ifndef XROOTD_WRITE_H
#define XROOTD_WRITE_H

#include "../ngx_xrootd_module.h"
#include "../compat/pgio.h"   /* xrdp_pg_bad_t */

/* kXR_write — write bytes from payload to an open file at a given offset. */
ngx_int_t xrootd_handle_write(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* Phase-42 W5 — inline write decompression for kXR_write.  Invoked from
 * xrootd_handle_write() ONLY when ctx->files[idx].write_codec != IDENTITY (an
 * opt-in handle opened for write with "?xrootd.compress=").  Decompresses the
 * payload — a self-contained codec frame — under a bomb guard and streams the
 * plaintext to pwrite at `offset`.  pgwrite never reaches here (stays plaintext).
 * `offset` is the PLAINTEXT file offset; `wlen` is the compressed payload length. */
ngx_int_t xrootd_write_compressed(xrootd_ctx_t *ctx, ngx_connection_t *c,
                                  int idx, int64_t offset, size_t wlen);

/* kXR_pgwrite — page-aligned write with per-4096-byte CRC validation. */
ngx_int_t xrootd_handle_pgwrite(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* kXR_writev — multi-segment scatter write, one pwrite per segment. */
ngx_int_t xrootd_handle_writev(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* kXR_sync — fsync(2) the file referenced by the handle. */
ngx_int_t xrootd_handle_sync(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* kXR_truncate — ftruncate the path named in the payload. */
ngx_int_t xrootd_handle_truncate(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* kXR_mkdir — create a directory (with optional kXR_mkpth parent creation). */
ngx_int_t xrootd_handle_mkdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* kXR_rm — unlink a file. */
ngx_int_t xrootd_handle_rm(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* kXR_rmdir — remove an empty directory. */
ngx_int_t xrootd_handle_rmdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* kXR_mv — rename a file or directory. */
ngx_int_t xrootd_handle_mv(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* kXR_chmod — change the permission bits of a file or directory. */
ngx_int_t xrootd_handle_chmod(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_pgwrite_decode_payload — decode a kXR_pgwrite payload into a flat
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
ngx_int_t xrootd_pgwrite_decode_payload(const u_char *payload,
    size_t payload_len, int64_t offset, u_char *flat, size_t *flat_len,
    int64_t *bad_offset);

/*
 * xrootd_try_post_write_aio — allocate an AIO write task and post it to the
 * thread pool.
 *
 * If no thread pool is configured (conf->common.thread_pool == NULL), returns NGX_OK
 * with *posted = 0 so the caller falls back to synchronous pwrite.
 *
 * payload_to_free: if non-NULL, this buffer is freed by the done callback
 *   after the write completes (used when the payload has been detached from
 *   ctx->payload_buf).
 *
 * bad / bad_count: pgwrite CSE bad-page list (NULL/0 for plain kXR_write). When
 *   non-empty the done callback emits a CSE retransmit frame; the list is copied
 *   into the task so the caller's stack buffer need not outlive the post.
 *
 * Returns NGX_OK (task posted or not posted), NGX_ERROR on task alloc failure.
 */
ngx_int_t xrootd_try_post_write_aio(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int idx, off_t offset, const u_char *data, size_t len,
    int64_t req_offset, ngx_uint_t is_pgwrite, u_char *payload_to_free,
    const xrdp_pg_bad_t *bad, size_t bad_count,
    const char *fallback_log, ngx_flag_t *posted);

#endif /* XROOTD_WRITE_H */
