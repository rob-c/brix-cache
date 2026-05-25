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

#include <errno.h>
#include <unistd.h>
#include <zlib.h>

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

    buf = ngx_pnalloc(r->pool, summary.bytes + 1);
    if (buf == NULL) {
        return NGX_ERROR;
    }

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

/* Feed one input chunk through inflate, writing all output to dst_fd.
 * Caller sets zs->next_in and zs->avail_in before calling. */
static ngx_int_t
inflate_feed(z_stream *zs, ngx_log_t *log, ngx_fd_t dst_fd,
    const char *log_path, off_t *dst_off, u_char *outbuf,
    const u_char *in, size_t in_len)
{
    int  zrc;

    zs->next_in  = (Bytef *) in;
    zs->avail_in = (uInt) in_len;

    do {
        size_t  produced;

        zs->next_out  = (Bytef *) outbuf;
        zs->avail_out = XROOTD_INFLATE_OUT_BUFSZ;

        zrc = inflate(zs, Z_NO_FLUSH);
        if (zrc == Z_STREAM_ERROR || zrc == Z_DATA_ERROR
            || zrc == Z_MEM_ERROR || zrc == Z_NEED_DICT)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_http_body: inflate error %d (%s) for %s",
                          zrc, zs->msg ? zs->msg : "",
                          log_path ? log_path : "-");
            return NGX_ERROR;
        }

        produced = XROOTD_INFLATE_OUT_BUFSZ - zs->avail_out;
        if (produced > 0) {
            if (xrootd_http_body_pwrite_full(log, dst_fd, outbuf,
                                              produced, dst_off, log_path)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    } while (zs->avail_in > 0 && zrc != Z_STREAM_END);

    return NGX_OK;
}

ngx_int_t
xrootd_http_body_inflate_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, int window_bits,
    xrootd_http_body_summary_t *summary_out)
{
    ngx_chain_t                *cl;
    z_stream                    zs;
    off_t                       dst_off = 0;
    ngx_int_t                   rc = NGX_ERROR;
    u_char                     *outbuf = NULL;
    u_char                     *inbuf = NULL;
    int                         zs_inited = 0;
    ngx_log_t                  *log;
    xrootd_http_body_summary_t  summary;

    if (summary_out == NULL) {
        summary_out = &summary;
    }

    if (xrootd_http_body_summary(r, summary_out) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r == NULL || r->request_body == NULL
        || r->request_body->bufs == NULL)
    {
        return NGX_OK;
    }

    log = r->connection->log;

    outbuf = ngx_alloc(XROOTD_INFLATE_OUT_BUFSZ, log);
    if (outbuf == NULL) {
        goto cleanup;
    }

    if (summary_out->has_spooled) {
        inbuf = ngx_alloc(XROOTD_INFLATE_IN_BUFSZ, log);
        if (inbuf == NULL) {
            goto cleanup;
        }
    }

    ngx_memzero(&zs, sizeof(zs));

    if (inflateInit2(&zs, window_bits) != Z_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_http_body: inflateInit2(%d) failed for %s",
                      window_bits, log_path ? log_path : "-");
        goto cleanup;
    }
    zs_inited = 1;

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
                                  "xrootd_http_body: inflate pread failed for %s",
                                  log_path ? log_path : "-");
                    goto cleanup;
                }

                file_off += (off_t) n;

                if (inflate_feed(&zs, log, dst_fd, log_path, &dst_off,
                                 outbuf, inbuf, (size_t) n) != NGX_OK)
                {
                    goto cleanup;
                }
            }

        } else {
            if (b->pos >= b->last) {
                continue;
            }

            if (inflate_feed(&zs, log, dst_fd, log_path, &dst_off,
                             outbuf, b->pos,
                             (size_t) (b->last - b->pos)) != NGX_OK)
            {
                goto cleanup;
            }
        }
    }

    rc = NGX_OK;

cleanup:
    if (zs_inited) {
        inflateEnd(&zs);
    }
    ngx_free(inbuf);
    ngx_free(outbuf);
    return rc;
}
