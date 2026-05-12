/*
 * io.c - blocking file write helpers shared by PUT handlers.
 */

#include "webdav.h"

#include <sys/syscall.h>
#include <unistd.h>

/*
 * webdav_write_full — write all len bytes to fd, retrying on EINTR.
 *
 * Uses sequential write(2), not pwrite(2), so the file offset advances.
 * Suitable for sequential PUT writes where offset tracking is done by the
 * caller.
 *
 * Returns: NGX_OK if all bytes were written; NGX_ERROR on any I/O failure.
 */
ngx_int_t
webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len)
{
    while (len > 0) {
        ssize_t nwritten;

        nwritten = write(fd, buf, len);
        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NGX_ERROR;
        }

        if (nwritten == 0) {
            errno = EIO;
            return NGX_ERROR;
        }

        buf += (size_t) nwritten;
        len -= (size_t) nwritten;
    }

    return NGX_OK;
}

ngx_int_t
webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd, ngx_buf_t *buf,
                         const char *path, u_char **scratch)
{
    off_t   src_off;
    size_t  remaining;

    if (buf->file == NULL || buf->file->fd == NGX_INVALID_FILE) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    src_off = buf->file_pos;
    remaining = (size_t) (buf->file_last - buf->file_pos);

#if defined(__linux__) && defined(SYS_copy_file_range)
    while (remaining > 0) {
        size_t  want;
        ssize_t copied;

        want = remaining > WEBDAV_PUT_COPY_CHUNK
                   ? WEBDAV_PUT_COPY_CHUNK
                   : remaining;

        copied = syscall(SYS_copy_file_range, buf->file->fd, &src_off,
                         dst_fd, NULL, want, 0);
        if (copied > 0) {
            remaining -= (size_t) copied;
            continue;
        }

        if (copied == 0) {
            errno = EIO;
            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, errno,
                "xrootd_webdav: copy_file_range() hit unexpected EOF for",
                path);
            return NGX_ERROR;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno != ENOSYS
            && errno != EOPNOTSUPP
            && errno != EINVAL
            && errno != EXDEV
            && errno != EPERM)
        {
            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, errno,
                "xrootd_webdav: copy_file_range() failed for",
                path);
            return NGX_ERROR;
        }

        break;
    }

    if (remaining == 0) {
        return NGX_OK;
    }
#endif

    if (*scratch == NULL) {
        *scratch = ngx_palloc(r->pool, WEBDAV_PUT_COPY_BUFSZ);
        if (*scratch == NULL) {
            return NGX_ERROR;
        }
    }

    while (remaining > 0) {
        size_t  chunk;
        ssize_t nread;

        chunk = remaining > WEBDAV_PUT_COPY_BUFSZ
                    ? WEBDAV_PUT_COPY_BUFSZ
                    : remaining;

        nread = pread(buf->file->fd, *scratch, chunk, src_off);
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }

            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, errno,
                "xrootd_webdav: pread() failed for",
                path);
            return NGX_ERROR;
        }

        if (nread == 0) {
            errno = EIO;
            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, errno,
                "xrootd_webdav: short temp-file body read for",
                path);
            return NGX_ERROR;
        }

        if (webdav_write_full(dst_fd, *scratch, (size_t) nread) != NGX_OK) {
            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, ngx_errno,
                "xrootd_webdav: write() failed for",
                path);
            return NGX_ERROR;
        }

        src_off += (off_t) nread;
        remaining -= (size_t) nread;
    }

    return NGX_OK;
}
