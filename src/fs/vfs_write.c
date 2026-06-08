#include "vfs_internal.h"
#include "../cache/writethrough.h"

ngx_int_t
xrootd_vfs_pwrite_full(ngx_fd_t fd, const u_char *buf, size_t len,
    off_t offset)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = pwrite(fd, buf + done, len - done, offset + (off_t) done);

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

        done += (size_t) n;
    }

    return NGX_OK;
}

static ngx_int_t
xrootd_vfs_write_file_buf(xrootd_vfs_file_t *fh, ngx_buf_t *b,
    off_t *dst_off, uint32_t *crc)
{
    u_char  tmp[XROOTD_VFS_COPY_CHUNK];
    off_t   pos;
    size_t  remaining;

    if (b->file == NULL || b->file->fd == NGX_INVALID_FILE
        || b->file_last < b->file_pos)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    pos = b->file_pos;
    remaining = (size_t) (b->file_last - b->file_pos);

    while (remaining > 0) {
        size_t chunk = remaining > sizeof(tmp) ? sizeof(tmp) : remaining;
        size_t got;

        if (xrootd_vfs_pread_full(b->file->fd, tmp, chunk, pos, &got)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        if (got != chunk) {
            errno = EIO;
            return NGX_ERROR;
        }

        if (xrootd_vfs_pwrite_full(fh->fd, tmp, chunk, *dst_off) != NGX_OK) {
            return NGX_ERROR;
        }

        if (crc != NULL) {
            *crc = xrootd_crc32c_extend(*crc, tmp, chunk);
        }

        pos += (off_t) chunk;
        *dst_off += (off_t) chunk;
        remaining -= chunk;
    }

    return NGX_OK;
}

static ngx_int_t
xrootd_vfs_write_memory_buf(xrootd_vfs_file_t *fh, ngx_buf_t *b,
    off_t *dst_off, uint32_t *crc)
{
    size_t len;

    if (b->last < b->pos) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    len = (size_t) (b->last - b->pos);
    if (len == 0) {
        return NGX_OK;
    }

    if (xrootd_vfs_pwrite_full(fh->fd, b->pos, len, *dst_off) != NGX_OK) {
        return NGX_ERROR;
    }

    if (crc != NULL) {
        *crc = xrootd_crc32c_extend(*crc, b->pos, len);
    }

    *dst_off += (off_t) len;
    return NGX_OK;
}

static size_t
xrootd_vfs_write_chain_length(ngx_chain_t *in)
{
    ngx_chain_t *cl;
    size_t       total;

    total = 0;
    for (cl = in; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        if (b == NULL) {
            continue;
        }

        if (b->in_file && b->file_last >= b->file_pos) {
            total += (size_t) (b->file_last - b->file_pos);
        } else if (ngx_buf_in_memory(b) && b->last >= b->pos) {
            total += (size_t) (b->last - b->pos);
        }
    }

    return total;
}

ngx_int_t
xrootd_vfs_write(xrootd_vfs_file_t *fh, off_t offset, ngx_chain_t *in,
    xrootd_vfs_io_result_t *result)
{
    ngx_chain_t *cl;
    off_t        dst_off;
    uint32_t     crc = 0;
    uint32_t    *crc_p = NULL;
    size_t       planned;
    size_t       observed;
    ngx_int_t    rc = NGX_OK;
    ngx_msec_t   start;
    int          saved_errno = 0;

    start = ngx_current_msec;

    if (result != NULL) {
        ngx_memzero(result, sizeof(*result));
        result->offset = offset;
    }

    if (fh == NULL || fh->fd == NGX_INVALID_FILE || offset < 0) {
        errno = EINVAL;
        saved_errno = errno;
        xrootd_vfs_observe_file_op(fh, XROOTD_METRIC_OP_WRITE, result, 0,
                                   NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    planned = xrootd_vfs_write_chain_length(in);
    if (xrootd_cache_should_writethrough(fh->ctx, offset, planned)
        != XROOTD_WT_DECISION_DENY)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, fh->log, 0,
                       "xrootd_vfs: writethrough eligible offset=%O len=%uz",
                       offset, planned);
    }

    if (fh->ctx != NULL && fh->ctx->want_pgcrc) {
        crc_p = &crc;
    }

    dst_off = offset;
    for (cl = in; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        if (b == NULL) {
            continue;
        }

        if (b->in_file) {
            if (xrootd_vfs_write_file_buf(fh, b, &dst_off, crc_p) != NGX_OK) {
                rc = NGX_ERROR;
                saved_errno = errno;
                goto done;
            }
        } else if (ngx_buf_in_memory(b)) {
            if (xrootd_vfs_write_memory_buf(fh, b, &dst_off, crc_p) != NGX_OK) {
                rc = NGX_ERROR;
                saved_errno = errno;
                goto done;
            }
        }
    }

    if (result != NULL && rc == NGX_OK) {
        result->length = (size_t) (dst_off - offset);
        result->crc32c = crc;
    }

    if (rc == NGX_OK && dst_off > fh->size) {
        fh->size = dst_off;
    }

done:
    observed = rc == NGX_OK ? (size_t) (dst_off - offset) : 0;
    xrootd_vfs_observe_file_op(fh, XROOTD_METRIC_OP_WRITE, result, observed,
                               rc, saved_errno, start);
    return rc;
}
