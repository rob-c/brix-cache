/*
 * http_compress.h — outbound (GET) HTTP response compression.
 *
 * WHAT: Accept-Encoding negotiation + on-the-fly response compression for the
 *       shared file-serve path (WebDAV GET / S3 GetObject). Off by default
 *       (per-location config); when enabled and the client advertises a codec we
 *       support, the GET body is streamed compressed with a Content-Encoding +
 *       Vary header instead of via zero-copy sendfile.
 * WHY:  phase-42 outbound parity/extension — XRootD's HTTP stack does no content
 *       compression; this lets clients fetch compressible objects pre-compressed.
 * HOW:  negotiate() picks the best available codec from Accept-Encoding (skipping
 *       ranges, tiny files, and already-compressed MIME types); send_compressed()
 *       sets chunked headers and streams read -> codec compress -> output filter.
 */
#ifndef XROOTD_COMPAT_HTTP_COMPRESS_H
#define XROOTD_COMPAT_HTTP_COMPRESS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "codec_core.h"

/* Don't bother compressing objects smaller than this (overhead dominates). */
#define XROOTD_COMPRESS_MIN_SIZE  256

/*
 * xrootd_http_compress_negotiate - choose an outbound codec for this GET.
 *
 * Returns the codec id to use, or XROOTD_CODEC_IDENTITY (= do not compress) when
 * compression is disabled, the request is a Range/HEAD request, the file is too
 * small, the content-type is already-compressed, or the client's Accept-Encoding
 * names no codec we have. The chosen codec is always one that is available.
 */
xrootd_codec_id_t xrootd_http_compress_negotiate(ngx_http_request_t *r,
    off_t file_size, ngx_flag_t is_range);

/*
 * xrootd_http_send_file_compressed - send a file body compressed with `codec`.
 *
 * Sets status 200 + ETag/Last-Modified (via set_file_headers), forces chunked
 * transfer (Content-Length unknown), adds Content-Encoding + Vary, sends the
 * header, then streams the whole file [0,size) through the codec to the output
 * filter (last buffer flagged last_buf). Takes ownership of send_fd (closes it).
 * Returns NGX_OK / NGX_ERROR / NGX_HTTP_INTERNAL_SERVER_ERROR.
 */
ngx_int_t xrootd_http_send_file_compressed(ngx_http_request_t *r,
    ngx_fd_t send_fd, const char *fs_path, off_t size,
    xrootd_codec_id_t codec, time_t mtime, unsigned etag_flags,
    off_t *bytes_in_out);

#endif /* XROOTD_COMPAT_HTTP_COMPRESS_H */
