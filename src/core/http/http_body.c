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
 *      write_buf delegates brix_copy_range() for file-backed, pwrite_full loop
 *      for memory-backed; read_all allocates ngx_pnalloc(r->pool) and reads via
 *      pread/ngx_memcpy with EINTR retry. The codec-based decompress-to-fd
 *      pipeline lives in the sibling http_body_decode.c; the shared output-drain
 *      helper below (brix_http_body_pwrite_full) is exported to it via
 *      http_body_internal.h.
*/

#include "http_body.h"
#include "http_body_internal.h"
#include "core/compat/copy_range.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_pread_full / pwrite_full (storage seam) */

#include <errno.h>
#include <unistd.h>
#include "core/compat/alloc_guard.h"

/*
 * brix_http_body_pwrite_full - loop pwrite to drain memory buffer into fd.
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

ngx_int_t
brix_http_body_pwrite_full(ngx_log_t *log, ngx_fd_t fd, const u_char *data,
    size_t len, off_t *off, const char *path)
{
    /* Delegate the EINTR/short-write loop to the VFS primitive (routes the byte
     * syscall through the storage seam); keep the path-tagged error log and the
     * caller's running offset. */
    if (brix_vfs_pwrite_full(fd, data, len, *off) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "brix_http_body: pwrite failed for %s",
                      path ? path : "-");
        return NGX_ERROR;
    }
    *off += (off_t) len;
    return NGX_OK;
}

/*
 * brix_http_body_summary - measure the request body without copying it.
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
brix_http_body_summary(ngx_http_request_t *r,
    brix_http_body_summary_t *out)
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
 * brix_http_body_write_buf - write one body buffer to dst_fd at *dst_off.
 *
 * WHAT: appends a single ngx_buf_t's payload at *dst_off and advances *dst_off
 *       by the number of bytes written.
 * WHY:  the two buffer kinds need different syscalls — a spooled buffer is
 *       fd-to-fd so it can use the zero-copy copy_range path, while a memory
 *       buffer must be pushed out with pwrite.
 * HOW:  in_file -> brix_copy_range(src fd@file_pos -> dst_fd@*dst_off);
 *       memory -> pwrite_full(pos..last). Empty buffers are a no-op success.
 *       errno is set on the EINVAL guard paths so callers can map it.
 */
ngx_int_t
brix_http_body_write_buf(ngx_http_request_t *r, ngx_fd_t dst_fd,
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

        if (brix_copy_range(r->connection->log, buf->file->fd,
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

    return brix_http_body_pwrite_full(r->connection->log, dst_fd, buf->pos,
                                        (size_t) (buf->last - buf->pos),
                                        dst_off, log_path);
}

/*
 * brix_http_body_write_to_fd - write the whole request body to dst_fd.
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
brix_http_body_write_to_fd(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, brix_http_body_summary_t *summary_out)
{
    ngx_chain_t                *cl;
    off_t                       off;
    brix_http_body_summary_t  summary;

    if (summary_out == NULL) {
        summary_out = &summary;
    }

    if (brix_http_body_summary(r, summary_out) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r == NULL || r->request_body == NULL) {
        return NGX_OK;
    }

    off = 0;
    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        if (brix_http_body_write_buf(r, dst_fd, cl->buf, &off, log_path)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * brix_http_body_write_to_fd_at — like brix_http_body_write_to_fd, but the
 * body lands starting at absolute offset base_off (via pwrite/copy_range), for
 * resumable Content-Range PUT where a chunk fills [base_off, base_off+len).
 */
ngx_int_t
brix_http_body_write_to_fd_at(ngx_http_request_t *r, ngx_fd_t dst_fd,
    const char *log_path, brix_http_body_summary_t *summary_out, off_t base_off)
{
    ngx_chain_t                *cl;
    off_t                       off;
    brix_http_body_summary_t  summary;

    if (summary_out == NULL) {
        summary_out = &summary;
    }
    if (brix_http_body_summary(r, summary_out) != NGX_OK) {
        return NGX_ERROR;
    }
    if (r == NULL || r->request_body == NULL) {
        return NGX_OK;
    }

    off = base_off;
    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        if (brix_http_body_write_buf(r, dst_fd, cl->buf, &off, log_path)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/*
 * brix_http_body_staged_spooled_buf — stage one spooled (in_file) body buffer.
 *
 * WHAT: reads buf[file_pos..file_last] from its temp fd in 64 KiB chunks and
 *       forwards each chunk to brix_vfs_staged_write at the running *off,
 *       advancing *off by the bytes staged.
 * WHY:  a spooled nginx buffer has no in-memory payload, so it must be pread out
 *       of its temp fd before the object driver can accept it; factoring this
 *       out keeps the write_to_staged orchestrator flat and under the CCN gate.
 * HOW:  validate the file handle (missing fd / last<pos -> EINVAL); loop pread
 *       (EINTR-retry, n==0 -> EIO) into a stack chunk, stage each read, advance
 *       both the source position and the destination *off. Behaviour is byte-
 *       identical to the previous inline loop.
 */
static ngx_int_t
brix_http_body_staged_spooled_buf(brix_vfs_staged_t *st, ngx_buf_t *b,
    off_t *off)
{
    off_t fpos;

    if (b->file == NULL || b->file->fd == NGX_INVALID_FILE
        || b->file_last < b->file_pos)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    for (fpos = b->file_pos; fpos < b->file_last; ) {
        u_char  chunk[65536];
        size_t  want = (size_t) (b->file_last - fpos);
        ssize_t n;

        if (want > sizeof(chunk)) {
            want = sizeof(chunk);
        }
        n = pread(b->file->fd, chunk, want, fpos);
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
        if (brix_vfs_staged_write(st, chunk, (size_t) n, *off) != NGX_OK) {
            return NGX_ERROR;
        }
        *off += n;
        fpos += n;
    }

    return NGX_OK;
}

/*
 * brix_http_body_write_to_staged — stream the whole request body into a staged
 * object via brix_vfs_staged_write (a driver-backed/object export has no kernel
 * fd, so write_to_fd does not apply). Memory buffers are forwarded directly;
 * spooled (in_file) buffers are read from their temp fd in 64 KiB chunks. The
 * destination offset runs from 0 so the body lands contiguously.
 */
ngx_int_t
brix_http_body_write_to_staged(ngx_http_request_t *r,
    brix_vfs_staged_t *st)
{
    ngx_chain_t *cl;
    off_t        off = 0;

    if (r == NULL || st == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (r->request_body == NULL) {
        return NGX_OK;
    }

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        if (b == NULL) {
            continue;
        }

        if (b->in_file) {
            if (brix_http_body_staged_spooled_buf(st, b, &off) != NGX_OK) {
                return NGX_ERROR;
            }

        } else if (b->pos < b->last) {
            size_t len = (size_t) (b->last - b->pos);

            if (brix_vfs_staged_write(st, b->pos, len, off) != NGX_OK) {
                return NGX_ERROR;
            }
            off += (off_t) len;
        }
    }

    return NGX_OK;
}

ngx_int_t
brix_http_body_write_to_writer(ngx_http_request_t *r, brix_vfs_writer_t *w)
{
    ngx_chain_t *cl;
    off_t        off = 0;

    if (r == NULL || w == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (r->request_body == NULL) {
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
                errno = EINVAL;
                return NGX_ERROR;
            }
            if (b->file_last > b->file_pos) {
                size_t len = (size_t) (b->file_last - b->file_pos);

                if (brix_vfs_writer_write_fd(w, b->file->fd, b->file_pos, len,
                                             off) != NGX_OK)
                {
                    return NGX_ERROR;
                }
                off += (off_t) len;
            }

        } else if (b->pos < b->last) {
            size_t len = (size_t) (b->last - b->pos);

            if (brix_vfs_writer_write(w, b->pos, len, off) != NGX_OK) {
                return NGX_ERROR;
            }
            off += (off_t) len;
        }
    }

    return NGX_OK;
}

/*
 * brix_http_body_read_all - copy the entire body into one pool buffer.
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
brix_http_body_read_all(ngx_http_request_t *r, size_t max_bytes,
    u_char **out, size_t *out_len)
{
    ngx_chain_t                *cl;
    brix_http_body_summary_t  summary;
    u_char                     *buf;
    size_t                      pos;

    if (out == NULL || out_len == NULL) {
        return NGX_ERROR;
    }

    *out = NULL;
    *out_len = 0;

    if (brix_http_body_summary(r, &summary) != NGX_OK) {
        return NGX_ERROR;
    }

    if (summary.bytes > max_bytes) {
        return NGX_DECLINED;
    }

    BRIX_PNALLOC_OR_RETURN(buf, r->pool, summary.bytes + 1, NGX_ERROR);

    pos = 0;
    if (r->request_body != NULL) {
        for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
            ngx_buf_t *b = cl->buf;

            if (b == NULL) {
                continue;
            }

            if (b->in_file) {
                size_t want = (size_t) (b->file_last - b->file_pos);
                size_t got  = 0;

                /* One full read through the storage seam (EINTR/short-read handled
                 * by the primitive); a short fill is a premature EOF. */
                if (brix_vfs_pread_full(b->file->fd, buf + pos, want,
                                          b->file_pos, &got) != NGX_OK) {
                    return NGX_ERROR;
                }
                if (got < want) {
                    errno = EIO;
                    return NGX_ERROR;
                }
                pos += got;

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
 * brix_http_read_body - kick off async body reading and normalise the rc.
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
brix_http_read_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt handler)
{
    ngx_int_t  rc;

    rc = ngx_http_read_client_request_body(r, handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}
