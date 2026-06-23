/*
 * http_body.c - shared nginx request-body chain helpers.
 *
 * WHAT: Summarises, writes to fd, and reads from nginx request body chains
 *       (ngx_chain_t of ngx_buf_t). Handles both memory-backed and file-backed
 *       buffers uniformly across WebDAV PUT and S3 PUT operations.
 *
 * WHY: HTTP PUT requests carry body content in nginx's request_body->bufs chain,
 *      which mixes spooled-to-file and in-memory buffers. WebDAV and S3 handlers
 *      need to write, read, or summarise this chain without knowing buffer layout.
 *
 * HOW: summary walks chain counting file_last-file_pos + last-pos bytes;
 *      write_buf delegates xrootd_copy_range() for file-backed, pwrite_full loop
 *      for memory-backed; read_all allocates ngx_pnalloc(r->pool) and reads via
 *      pread/ngx_memcpy with EINTR retry.
*/

#include "http_body.h"
#include "copy_range.h"
#include "codec_core.h"

#include <errno.h>
#include <unistd.h>
#include "alloc_guard.h"

#define XROOTD_INFLATE_OUT_BUFSZ  (64 * 1024)
#define XROOTD_INFLATE_IN_BUFSZ   (64 * 1024)

/*
 * xrootd_http_body_pwrite_full - loop pwrite to drain memory buffer into fd.
 *
 * WHAT: Writes data[0..len] into fd at position *off via repeated pwrite calls,
 *       advancing off and shrinking len until all bytes written. Retries on EINTR,
 *       errors on zero-byte write or non-EINTR failure.
 *
 * WHY: Memory-backed nginx buffers (b->memory=1) must be written via pwrite since
 *      they have no file fd. This function handles partial writes and EINTR retries
 *      uniformly for all memory buffer paths in http_body.c.
 *
 * HOW: while(len>0): pwrite(fd, data, len, off). On n<0: retry EINTR, error otherwise.
 *      On n==0: errno=EIO + error. Advances data+=n, len-=n, off+=n until done.
 */

static ngx_int_t
xrootd_http_body_pwrite_full(ngx_log_t *log, ngx_fd_t fd, const u_char *data,
    size_t len, off_t *off, const char *path)
{
    while (len > 0) {
        ssize_t n;

        n = pwrite(fd, data, len, *off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd_http_body: pwrite failed for %s",
                          path ? path : "-");
            return NGX_ERROR;
        }

        if (n == 0) {
            errno = EIO;
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd_http_body: pwrite wrote zero bytes for %s",
                          path ? path : "-");
            return NGX_ERROR;
        }

        data += (size_t) n;
        len -= (size_t) n;
        *off += (off_t) n;
    }

    return NGX_OK;
}

/*
 * xrootd_http_body_summary - measure the request body without copying it.
 *
 * WHAT: walks request_body->bufs once, summing payload bytes and flagging
 *       whether memory-backed and/or spooled-to-file buffers are present.
 * WHY:  callers need the exact size up front (to allocate or to bound input)
 *       and need to know if a file path exists so they can pick copy_range vs
 *       pwrite, before touching any data.
 * HOW:  file buffers contribute file_last-file_pos; memory buffers contribute
 *       last-pos. A malformed file buffer (missing fd, or last<pos) is a hard
 *       NGX_ERROR rather than a silent skip.
 */
ngx_int_t
xrootd_http_body_summary(ngx_http_request_t *r,
    xrootd_http_body_summary_t *out)
{
    ngx_chain_t *cl;

    if (out == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(*out));

    if (r == NULL || r->request_body == NULL) {
        return NGX_OK;
    }

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        if (b == NULL) {
            continue;
        }

        if (b->in_file) {
            if (b->file == NULL || b->file->fd == NGX_INVALID_FILE
                || b->file_last < b->file_pos)
            {
                return NGX_ERROR;
            }
            out->has_spooled = 1;
            out->bytes += (size_t) (b->file_last - b->file_pos);

        } else if (b->pos < b->last) {
            out->has_memory = 1;
            out->bytes += (size_t) (b->last - b->pos);
        }
    }

    return NGX_OK;
}

/*
 * xrootd_http_body_write_buf - write one body buffer to dst_fd at *dst_off.
 *
 * WHAT: appends a single ngx_buf_t's payload at *dst_off and advances *dst_off
 *       by the number of bytes written.
 * WHY:  the two buffer kinds need different syscalls — a spooled buffer is
 *       fd-to-fd so it can use the zero-copy copy_range path, while a memory
 *       buffer must be pushed out with pwrite.
 * HOW:  in_file -> xrootd_copy_range(src fd@file_pos -> dst_fd@*dst_off);
 *       memory -> pwrite_full(pos..last). Empty buffers are a no-op success.
 *       errno is set on the EINVAL guard paths so callers can map it.
 */
ngx_int_t
xrootd_http_body_write_buf(ngx_http_request_t *r, ngx_fd_t dst_fd,
    ngx_buf_t *buf, off_t *dst_off, const char *log_path)
{
    size_t len;

    if (r == NULL || buf == NULL || dst_off == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (buf->in_file) {
        if (buf->file == NULL || buf->file->fd == NGX_INVALID_FILE
            || buf->file_last < buf->file_pos)
        {
            errno = EINVAL;
            return NGX_ERROR;
        }

        len = (size_t) (buf->file_last - buf->file_pos);
        if (len == 0) {
            return NGX_OK;
        }

        if (xrootd_copy_range(r->connection->log, buf->file->fd,
                              buf->file_pos, dst_fd, *dst_off, len,
                              log_path, log_path) != NGX_OK)
        {
            return NGX_ERROR;
        }

        *dst_off += (off_t) len;
        return NGX_OK;
    }

    if (buf->pos >= buf->last) {
        return NGX_OK;
    }

    return xrootd_http_body_pwrite_full(r->connection->log, dst_fd, buf->pos,
                                        (size_t) (buf->last - buf->pos),
                                        dst_off, log_path);
}

/*
 * xrootd_http_body_write_to_fd - write the whole request body to dst_fd.
 *
 * WHAT: streams every body buffer into dst_fd starting at offset 0, optionally
 *       returning the body summary to the caller.
 * WHY:  the common PUT path (WebDAV and S3) materialises the uploaded body to
 *       an already-open destination fd.
 * HOW:  summarise first (also validates the chain), then iterate buffers
 *       through write_buf, threading a running offset so each buffer lands
 *       contiguously. summary_out may be NULL — a local is used in that case.
 */
ngx_int_t
xrootd_http_body_write_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, xrootd_http_body_summary_t *summary_out)
{
    ngx_chain_t                *cl;
    off_t                       off;
    xrootd_http_body_summary_t  summary;

    if (summary_out == NULL) {
        summary_out = &summary;
    }

    if (xrootd_http_body_summary(r, summary_out) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r == NULL || r->request_body == NULL) {
        return NGX_OK;
    }

    off = 0;
    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        if (xrootd_http_body_write_buf(r, dst_fd, cl->buf, &off, log_path)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * xrootd_http_body_read_all - copy the entire body into one pool buffer.
 *
 * WHAT: allocates a single NUL-terminated buffer from r->pool and fills it
 *       with the whole body; returns it via *out / *out_len.
 * WHY:  small structured bodies (S3 multi-object delete, lockinfo, etc.) are
 *       easier to parse as one contiguous string than as a buffer chain.
 * HOW:  size via summary; refuse bodies larger than max_bytes with
 *       NGX_DECLINED (the buffer is never allocated in that case); then read
 *       file buffers via pread (EINTR-retry) and memcpy memory buffers, both
 *       appending at a running pos. Buffer is pool-owned (no free needed);
 *       the extra +1 byte holds the trailing '\0' (out_len excludes it).
 */
ngx_int_t
xrootd_http_body_read_all(ngx_http_request_t *r, size_t max_bytes,
    u_char **out, size_t *out_len)
{
    ngx_chain_t                *cl;
    xrootd_http_body_summary_t  summary;
    u_char                     *buf;
    size_t                      pos;

    if (out == NULL || out_len == NULL) {
        return NGX_ERROR;
    }

    *out = NULL;
    *out_len = 0;

    if (xrootd_http_body_summary(r, &summary) != NGX_OK) {
        return NGX_ERROR;
    }

    if (summary.bytes > max_bytes) {
        return NGX_DECLINED;
    }

    XROOTD_PNALLOC_OR_RETURN(buf, r->pool, summary.bytes + 1, NGX_ERROR);

    pos = 0;
    if (r->request_body != NULL) {
        for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
            ngx_buf_t *b = cl->buf;

            if (b == NULL) {
                continue;
            }

            if (b->in_file) {
                off_t off = b->file_pos;

                while (off < b->file_last) {
                    size_t  want;
                    ssize_t n;

                    want = (size_t) (b->file_last - off);
                    n = pread(b->file->fd, buf + pos, want, off);
                    if (n < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        return NGX_ERROR;
                    }
                    if (n == 0) {
                        errno = EIO;
                        return NGX_ERROR;
                    }

                    off += (off_t) n;
                    pos += (size_t) n;
                }

            } else if (b->pos < b->last) {
                size_t n = (size_t) (b->last - b->pos);

                ngx_memcpy(buf + pos, b->pos, n);
                pos += n;
            }
        }
    }

    buf[pos] = '\0';
    *out = buf;
    *out_len = pos;
    return NGX_OK;
}

/*
 * xrootd_http_read_body - kick off async body reading and normalise the rc.
 *
 * WHAT: thin wrapper over ngx_http_read_client_request_body that maps nginx's
 *       return convention onto this module's.
 * WHY:  the body usually is not fully buffered yet; nginx will invoke handler
 *       later. Callers must propagate the returned rc out of their method
 *       handler so the request stays suspended until the body arrives.
 * HOW:  an error rc (>= NGX_HTTP_SPECIAL_RESPONSE) is returned verbatim as the
 *       response status; otherwise return NGX_DONE so nginx holds the request
 *       open and re-enters via handler when the body is ready.
 */
ngx_int_t
xrootd_http_read_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt handler)
{
    ngx_int_t  rc;

    rc = ngx_http_read_client_request_body(r, handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}

/* Feed one input chunk through the codec stream, writing all produced output to
 * dst_fd. finish!=0 marks the final input. *ended is set when the codec reports
 * end-of-stream. *worst_rc captures the first negative codec rc (for the caller's
 * HTTP-status mapping: ERR_BOMB -> 413, ERR_DATA -> 400). Returns NGX_OK/ERROR. */
static ngx_int_t
codec_feed(xrootd_codec_stream_t *s, ngx_log_t *log, ngx_fd_t dst_fd,
    const char *log_path, off_t *dst_off, u_char *outbuf,
    const u_char *in, size_t in_len, int finish, int *ended,
    xrootd_codec_rc_t *worst_rc)
{
    size_t  ip = 0;

    for (;;) {
        size_t             op = 0;
        xrootd_codec_rc_t  rc;

        rc = xrootd_codec_step(s, (const uint8_t *) in, in_len, &ip,
                               (uint8_t *) outbuf, XROOTD_INFLATE_OUT_BUFSZ,
                               &op, finish);
        if (rc < 0) {
            *worst_rc = rc;
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_http_body: decode error %d for %s",
                          (int) rc, log_path ? log_path : "-");
            return NGX_ERROR;
        }
        if (op > 0) {
            if (xrootd_http_body_pwrite_full(log, dst_fd, outbuf, op,
                                             dst_off, log_path) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
        if (rc == XROOTD_CODEC_END) {
            *ended = 1;
            return NGX_OK;
        }
        if (op == XROOTD_INFLATE_OUT_BUFSZ) {
            continue;                 /* output buffer was full: drain more */
        }
        if (ip < in_len) {
            continue;                 /* input remains in this chunk */
        }
        return NGX_OK;                /* chunk consumed, output drained */
    }
}

/*
 * codec_decode_bufs — feed every request-body buffer through an open codec
 * stream, writing decompressed bytes to dst_fd, then finalise.
 *
 * In-memory buffers feed directly; spooled buffers are pread in
 * XROOTD_INFLATE_IN_BUFSZ chunks into inbuf first. After the last buffer a final
 * flush (empty input, finish=1) drains any tail; if the codec never reports
 * end-of-stream the input was truncated/corrupt (ERR_DATA -> caller maps 400).
 * Flat, early-return cleanup; the stream + buffers are owned by the caller.
 */
static ngx_int_t
codec_decode_bufs(xrootd_codec_stream_t *s, ngx_http_request_t *r,
    ngx_fd_t dst_fd, const char *log_path, u_char *outbuf, u_char *inbuf,
    ngx_log_t *log, xrootd_codec_rc_t *worst_rc)
{
    ngx_chain_t *cl;
    off_t        dst_off = 0;
    int          ended = 0;

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        if (b == NULL) {
            continue;
        }

        if (b->in_file) {
            off_t  file_off = b->file_pos;

            while (file_off < b->file_last) {
                size_t   want;
                ssize_t  n;

                want = (size_t) (b->file_last - file_off);
                if (want > XROOTD_INFLATE_IN_BUFSZ) {
                    want = XROOTD_INFLATE_IN_BUFSZ;
                }
                do {
                    n = pread(b->file->fd, inbuf, want, file_off);
                } while (n < 0 && errno == EINTR);
                if (n <= 0) {
                    ngx_log_error(NGX_LOG_ERR, log, errno,
                                  "xrootd_http_body: decode pread failed for %s",
                                  log_path ? log_path : "-");
                    return NGX_ERROR;
                }
                file_off += (off_t) n;
                if (codec_feed(s, log, dst_fd, log_path, &dst_off, outbuf,
                               inbuf, (size_t) n, 0, &ended, worst_rc) != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

        } else if (b->pos < b->last) {
            if (codec_feed(s, log, dst_fd, log_path, &dst_off, outbuf,
                           b->pos, (size_t) (b->last - b->pos), 0, &ended,
                           worst_rc) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    /* Final flush: signal end-of-input and drain the codec's tail. */
    if (!ended) {
        if (codec_feed(s, log, dst_fd, log_path, &dst_off, outbuf,
                       (const u_char *) "", 0, 1, &ended, worst_rc) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    if (!ended) {
        /* All input consumed + finish, but no end-of-stream: truncated input. */
        *worst_rc = XROOTD_CODEC_ERR_DATA;
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_http_body: truncated compressed body for %s",
                      log_path ? log_path : "-");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * xrootd_http_body_decode_ratio - choose the untrusted decode ratio ceiling.
 *
 * WHAT: Returns the maximum permitted output:input expansion ratio for the given
 *       Content-Encoding codec on HTTP request-body decode.
 * WHY:  The generic 1000:1 ceiling catches classic bombs for most codecs, but LZ4
 *       frames cap zero-heavy compression below that; a lower LZ4-specific limit
 *       keeps PUT bomb protection effective without changing trusted decode paths.
 * HOW:  Select the codec-specific constant for LZ4, otherwise use the shared
 *       default consumed by the central codec guard.
 */
static uint32_t
xrootd_http_body_decode_ratio(xrootd_codec_id_t codec)
{
    if (codec == XROOTD_CODEC_LZ4) {
        return XROOTD_DECODE_LZ4_MAX_RATIO;
    }
    return XROOTD_DECODE_MAX_RATIO;
}

/*
 * xrootd_http_body_decode_to_fd - decompress the request body to dst_fd.
 *
 * WHAT: streams the Content-Encoding-selected codec over the request body chain,
 *       writing plaintext to dst_fd. Bounds output via the bomb guard (out_cap =
 *       max_output, ratio default) so a hostile highly-compressible upload cannot
 *       exhaust disk; on any failure sets *http_status_out (413 bomb / 400 bad
 *       data / 500 I-O) and returns NGX_ERROR. On success returns NGX_OK.
 * HOW:  open one xrootd_codec stream, hand the per-buffer feed loop to
 *       codec_decode_bufs, close once on return. Buffers freed here on all paths.
 */
ngx_int_t
xrootd_http_body_decode_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, xrootd_codec_id_t codec, uint64_t max_output,
    xrootd_http_body_summary_t *summary_out, ngx_int_t *http_status_out)
{
    xrootd_codec_stream_t      *s;
    xrootd_codec_guard_t        guard;
    xrootd_codec_rc_t           worst_rc = XROOTD_CODEC_OK;
    ngx_int_t                   rc;
    u_char                     *outbuf = NULL;
    u_char                     *inbuf = NULL;
    ngx_log_t                  *log;
    xrootd_http_body_summary_t  summary;

    if (summary_out == NULL) {
        summary_out = &summary;
    }
    if (xrootd_http_body_summary(r, summary_out) != NGX_OK) {
        if (http_status_out) { *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR; }
        return NGX_ERROR;
    }
    if (r == NULL || r->request_body == NULL
        || r->request_body->bufs == NULL)
    {
        return NGX_OK;
    }

    log = r->connection->log;

    ngx_memzero(&guard, sizeof(guard));
    guard.out_cap   = max_output;          /* 0 = unbounded */
    guard.max_ratio = xrootd_http_body_decode_ratio(codec);

    s = xrootd_codec_open(codec, XROOTD_CODEC_DIR_DECOMPRESS, -1, &guard);
    if (s == NULL) {
        if (http_status_out) {
            *http_status_out = NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_http_body: codec %d unavailable for %s",
                      (int) codec, log_path ? log_path : "-");
        return NGX_ERROR;
    }

    outbuf = ngx_alloc(XROOTD_INFLATE_OUT_BUFSZ, log);
    if (outbuf == NULL) {
        xrootd_codec_close(s);
        if (http_status_out) { *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR; }
        return NGX_ERROR;
    }
    if (summary_out->has_spooled) {
        inbuf = ngx_alloc(XROOTD_INFLATE_IN_BUFSZ, log);
        if (inbuf == NULL) {
            ngx_free(outbuf);
            xrootd_codec_close(s);
            if (http_status_out) { *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR; }
            return NGX_ERROR;
        }
    }

    rc = codec_decode_bufs(s, r, dst_fd, log_path, outbuf, inbuf, log, &worst_rc);

    ngx_free(inbuf);
    ngx_free(outbuf);
    xrootd_codec_close(s);

    if (rc != NGX_OK && http_status_out) {
        if (worst_rc == XROOTD_CODEC_ERR_BOMB) {
            *http_status_out = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;   /* 413 */
        } else if (worst_rc == XROOTD_CODEC_ERR_DATA) {
            *http_status_out = NGX_HTTP_BAD_REQUEST;                /* 400 */
        } else {
            *http_status_out = NGX_HTTP_INTERNAL_SERVER_ERROR;      /* 500 */
        }
    }
    return rc;
}

/*
 * xrootd_http_body_inflate_to_fd - compatibility wrapper (zlib window_bits).
 *
 * Maps the legacy window_bits selector (15+16 = gzip, 15 = deflate) onto the
 * codec abstraction and delegates to xrootd_http_body_decode_to_fd with no output
 * cap. Retained so existing callers keep working; new code should call
 * xrootd_http_body_decode_to_fd directly with a codec id + bomb cap.
 */
ngx_int_t
xrootd_http_body_inflate_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, int window_bits,
    xrootd_http_body_summary_t *summary_out)
{
    xrootd_codec_id_t codec = (window_bits >= 16)
                              ? XROOTD_CODEC_GZIP : XROOTD_CODEC_DEFLATE;

    return xrootd_http_body_decode_to_fd(r, dst_fd, log_path, codec, 0,
                                         summary_out, NULL);
}
