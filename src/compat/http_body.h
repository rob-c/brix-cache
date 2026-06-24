#ifndef XROOTD_COMPAT_HTTP_BODY_H
#define XROOTD_COMPAT_HTTP_BODY_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "codec_core.h"

/* Default decompression-bomb expansion-ratio ceiling for inbound (PUT) decode of
 * untrusted bodies: reject once output/input exceeds this (engages after 64 KiB
 * output). 1000:1 is well past any legitimate payload but short of a zip-bomb. */
#define XROOTD_DECODE_MAX_RATIO  1000

/* LZ4 frames do not reach the generic 1000:1 bomb threshold on zero-heavy
 * payloads, so untrusted HTTP decode uses a codec-specific ceiling that still
 * leaves ample room for ordinary compressible objects while rejecting compact
 * LZ4 bombs before they are stored. */
#define XROOTD_DECODE_LZ4_MAX_RATIO  200

/* Absolute output ceiling for inbound (PUT) decode, complementing the ratio
 * guard.  The ratio guard catches the classic tiny-input/huge-output bomb, but a
 * body whose expansion stays just under the ratio (e.g. ~900:1) yet is uploaded
 * near client_max_body_size could still decode to an enormous absolute size and
 * exhaust disk.  This finite per-request ceiling bounds that: 16 GiB is far above
 * any realistic single compressed PUT object (large objects are streamed/multipart
 * or stored uncompressed) yet caps the staged temp a hostile upload can produce.
 * A tripped cap maps to 413, exactly like the ratio guard. */
#define XROOTD_DECODE_MAX_OUTPUT  (16ULL * 1024 * 1024 * 1024)

/*
 * xrootd_http_body_summary_t — summary of nginx request body chain layout.
 *
 * WHAT: Struct holding total byte count + flags indicating whether the body contains
 *      memory-backed buffers (has_memory) or spooled-to-file buffers (has_spooled). WHY:
 *      WebDAV PUT and S3 PUT need to know body size and buffer types before writing. */

typedef struct {
    size_t      bytes;
    ngx_flag_t has_memory;
    ngx_flag_t has_spooled;
} xrootd_http_body_summary_t;

/*
 * xrootd_http_body_summary - scan request body chain and compute byte count + layout info.
 *
 * WHAT: Iterates over r->request_body->bufs, counts total bytes from both memory-backed
 *       and file-backed buffers, and sets has_memory/has_spooled flags.
 *
 * WHY: WebDAV PUT and S3 PUT need to know the body size before writing. This function
 *      provides a quick summary without reading all content, enabling size checks and
 *      allocation decisions.
 *
 * HOW: Walks ngx_chain_t of ngx_buf_t. For file-backed buffers uses (file_last - file_pos);
 *      for memory-backed buffers uses (last - pos). Returns NGX_OK or NGX_ERROR on invalid fd.
 */
ngx_int_t xrootd_http_body_summary(ngx_http_request_t *r,
    xrootd_http_body_summary_t *out);

/*
 * xrootd_http_body_write_buf - write a single request-body buffer to an fd.
 *
 * WHAT: Takes one ngx_buf_t from the request body chain and writes its contents to
 *       dst_fd at position *dst_off. Uses copy_file_range for file-backed buffers,
 *       pwrite for memory-backed buffers.
 *
 * WHY: WebDAV PUT and S3 PUT write the request body to a local file in chunks (one
 *      buffer at a time). This function handles both buffer types uniformly.
 *
 * HOW: For file-backed buf: xrootd_copy_range() from buf->file->fd to dst_fd.
 *      For memory-backed buf: xrootd_http_body_pwrite_full() loop pwrite with EINTR retry.
 */
ngx_int_t xrootd_http_body_write_buf(ngx_http_request_t *r, ngx_fd_t dst_fd,
    ngx_buf_t *buf, off_t *dst_off, const char *log_path);

/*
 * xrootd_http_body_write_to_fd - write entire request body to an fd.
 *
 * WHAT: Summarizes the request body, then iterates over all buffers writing each one
 *       to dst_fd via xrootd_http_body_write_buf(). Optionally returns summary stats.
 *
 * WHY: WebDAV PUT and S3 PUT need to write the full request body to a local file.
 *      This is the top-level entry point that handles the complete chain.
 *
 * HOW: Calls xrootd_http_body_summary() first, then loops over r->request_body->bufs
 *      calling xrootd_http_body_write_buf() for each buffer. Accumulates offset.
 */
ngx_int_t xrootd_http_body_write_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, xrootd_http_body_summary_t *summary_out);

/*
 * xrootd_http_body_write_to_fd_at - write the request body starting at absolute
 * offset base_off (for resumable Content-Range PUT).  Same as the _to_fd form
 * but seeds the running destination offset with base_off.
 */
ngx_int_t xrootd_http_body_write_to_fd_at(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, xrootd_http_body_summary_t *summary_out, off_t base_off);

/*
 * xrootd_http_body_read_all - read entire request body into a single allocated buffer.
 *
 * WHAT: Summarizes the request body, allocates a pool buffer of summary.bytes + 1,
 *       then reads all content (from both file-backed and memory buffers) into it
 *       as a null-terminated string. Returns via out/out_len.
 *
 * WHY: S3 signature verification needs the raw request body bytes. WebDAV operations
 *      that read body content need a contiguous buffer for processing.
 *
 * HOW: Calls xrootd_http_body_summary() to get byte count; rejects if > max_bytes.
 *      Allocates ngx_pnalloc(r->pool, summary.bytes+1). For file-backed buffers uses
 *      pread loop; for memory-backed buffers uses ngx_memcpy. Null-terminates result.
 */
ngx_int_t xrootd_http_body_read_all(ngx_http_request_t *r, size_t max_bytes,
    u_char **out, size_t *out_len);

/*
 * xrootd_http_read_body - dispatch async request-body reading.
 *
 * Wraps ngx_http_read_client_request_body() and normalises the return value:
 * returns NGX_DONE when body reading has started (handler will be called on
 * completion), or an HTTP status code (>= NGX_HTTP_SPECIAL_RESPONSE) if nginx
 * encountered an early error before the handler could be scheduled.
 *
 * WHY: Every body-reading handler repeats the same three lines:
 *   rc = ngx_http_read_client_request_body(r, cb);
 *   if (rc >= NGX_HTTP_SPECIAL_RESPONSE) { return rc; }
 *   return NGX_DONE;
 * Centralising the NGX_HTTP_SPECIAL_RESPONSE sentinel check removes an nginx
 * internals detail from protocol handlers and makes each dispatch site a
 * single expression.
 */
ngx_int_t xrootd_http_read_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt handler);

/*
 * xrootd_http_body_inflate_to_fd - decompress and write request body to an fd.
 *
 * WHAT: Decompress the nginx request body chain using zlib inflate and write the
 *       decompressed bytes to dst_fd. Handles both memory-backed and file-backed
 *       (spooled) buffers in the nginx body chain.
 *
 * WHY: WebDAV PUT and S3 PUT clients may send Content-Encoding: gzip or deflate.
 *      Without decompression the server would store compressed data verbatim.
 *
 * HOW: inflateInit2(window_bits): 15+16=gzip, 15=deflate (raw zlib). Feeds each
 *      buffer (memory direct; file via 64KB pread chunks) into inflate(), writing
 *      64KB output chunks via pwrite. inflateEnd() called on all exit paths.
 *
 * Parameters:
 *   window_bits — 31 (15+16) for gzip, 15 for deflate; passed to inflateInit2
 *   summary_out — optional; filled with compressed body byte count if non-NULL
 */
ngx_int_t xrootd_http_body_inflate_to_fd(ngx_http_request_t *r,
    ngx_fd_t dst_fd, const char *log_path, int window_bits,
    xrootd_http_body_summary_t *summary_out);

/*
 * xrootd_http_body_decode_to_fd - decompress a request body with any codec.
 *
 * WHAT: Streams the given codec (xrootd_codec_id_t — gzip/deflate/zstd/xz/brotli/
 *       bzip2) over the request body chain, writing plaintext to dst_fd, bounded
 *       by the decompression-bomb guard.
 * WHY:  WebDAV/S3 PUT may carry any supported Content-Encoding; the stored object
 *       must be the decoded bytes, streamed so a large/hostile body never lands
 *       fully in RAM or fills the disk.
 * HOW:  opens one xrootd_codec stream (DECOMPRESS) with guard{out_cap=max_output,
 *       max_ratio selected for codec}, feeds every body buffer, finalises.
 *
 * Parameters:
 *   codec          — selected codec id (caller maps Content-Encoding token).
 *   max_output     — hard output ceiling in bytes (0 = unbounded). Callers
 *                    should pass a sane cap for untrusted uploads.
 *   http_status_out— optional; on failure set to the HTTP status to return
 *                    (415 codec unavailable / 413 bomb / 400 corrupt / 500 I-O).
 * Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t xrootd_http_body_decode_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, xrootd_codec_id_t codec, uint64_t max_output,
    xrootd_http_body_summary_t *summary_out, ngx_int_t *http_status_out);

#endif /* XROOTD_COMPAT_HTTP_BODY_H */
