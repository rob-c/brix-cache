#include "vfs_internal.h"
#include "../cache/open.h"

ngx_int_t
xrootd_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len,
    off_t offset, size_t *nread)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = pread(fd, buf + done, len - done, offset + (off_t) done);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (nread != NULL) {
                *nread = done;
            }
            return NGX_ERROR;
        }

        if (n == 0) {
            break;
        }

        done += (size_t) n;
    }

    if (nread != NULL) {
        *nread = done;
    }

    return NGX_OK;
}

static ngx_int_t
xrootd_vfs_make_memory_chain(xrootd_vfs_file_t *fh, off_t offset,
    size_t length, ngx_chain_t **out, xrootd_vfs_io_result_t *result)
{
    ngx_buf_t    *b;
    ngx_chain_t  *link;
    u_char       *data;
    size_t        nread;

    data = ngx_pnalloc(fh->pool, length == 0 ? 1 : length);
    if (data == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    if (xrootd_vfs_pread_full(fh->fd, data, length, offset, &nread)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    b = ngx_pcalloc(fh->pool, sizeof(*b));
    link = ngx_alloc_chain_link(fh->pool);
    if (b == NULL || link == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    b->pos = data;
    b->last = data + nread;
    b->start = data;
    b->end = data + length;
    b->memory = 1;

    link->buf = b;
    link->next = NULL;
    *out = link;

    if (result != NULL && fh->ctx != NULL && fh->ctx->want_pgcrc) {
        result->crc32c = xrootd_crc32c_value(data, nread);
    }

    if (result != NULL) {
        result->length = nread;
        result->eof = nread < length ? 1 : result->eof;
    }

    return NGX_OK;
}

static ngx_int_t
xrootd_vfs_make_file_chain(xrootd_vfs_file_t *fh, off_t offset,
    size_t length, ngx_chain_t **out)
{
    ngx_buf_t    *b;
    ngx_chain_t  *link;
    ngx_fd_t      fd;
    size_t        path_len;

    fd = dup(fh->fd);
    if (fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    if (xrootd_vfs_register_fd_cleanup(fh->pool, fd, fh->path, fh->log)
        != NGX_OK)
    {
        int err = errno;
        ngx_close_file(fd);
        errno = err;
        return NGX_ERROR;
    }

    b = ngx_pcalloc(fh->pool, sizeof(*b));
    link = ngx_alloc_chain_link(fh->pool);
    if (b == NULL || link == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    b->file = ngx_pcalloc(fh->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    path_len = strlen(fh->path);
    b->file->name.data = ngx_pnalloc(fh->pool, path_len + 1);
    if (b->file->name.data == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memcpy(b->file->name.data, fh->path, path_len);
    b->file->name.data[path_len] = '\0';
    b->file->name.len = path_len;
    b->file->fd = fd;
    b->file->log = fh->log;

    b->in_file = 1;
    b->file_pos = offset;
    b->file_last = offset + (off_t) length;

    link->buf = b;
    link->next = NULL;
    *out = link;

    return NGX_OK;
}

ngx_int_t
xrootd_vfs_read(xrootd_vfs_file_t *fh, off_t offset, size_t length,
    ngx_chain_t **out, xrootd_vfs_io_result_t *result)
{
    size_t capped;
    size_t observed;
    ngx_int_t rc;
    ngx_msec_t start;
    int saved_errno;

    start = ngx_current_msec;

    if (out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    *out = NULL;

    if (result != NULL) {
        ngx_memzero(result, sizeof(*result));
        result->offset = offset;
        result->from_cache = fh != NULL ? fh->from_cache : 0;
    }

    if (fh == NULL || fh->fd == NGX_INVALID_FILE || offset < 0) {
        errno = EINVAL;
        saved_errno = errno;
        xrootd_vfs_observe_file_op(fh, XROOTD_METRIC_OP_READ, result, 0,
                                   NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (offset >= fh->size || length == 0) {
        if (result != NULL) {
            result->eof = 1;
        }
        xrootd_vfs_observe_file_op(fh, XROOTD_METRIC_OP_READ, result, 0,
                                   NGX_OK, 0, start);
        return NGX_OK;
    }

    capped = length;
    if ((off_t) capped > fh->size - offset) {
        capped = (size_t) (fh->size - offset);
        if (result != NULL) {
            result->eof = 1;
        }
    }

    if (result != NULL) {
        result->length = capped;
    }

    if (fh->is_tls || (fh->ctx != NULL && fh->ctx->want_pgcrc)) {
        rc = xrootd_vfs_make_memory_chain(fh, offset, capped, out, result);
    } else {
        rc = xrootd_vfs_make_file_chain(fh, offset, capped, out);
    }

    if (rc == NGX_OK && fh->from_cache && capped > 0) {
        (void) xrootd_cache_record_access(fh->path, capped, fh->log);
    }

    saved_errno = rc == NGX_OK ? 0 : errno;
    observed = 0;
    if (rc == NGX_OK) {
        observed = result != NULL ? result->length : capped;
    }
    xrootd_vfs_observe_file_op(fh, XROOTD_METRIC_OP_READ, result, observed,
                               rc, saved_errno, start);
    return rc;
}
