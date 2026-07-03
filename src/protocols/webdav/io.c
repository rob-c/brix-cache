/*
 * io.c - blocking file write helpers shared by PUT handlers.
 */

#include "webdav.h"
#include "core/http/http_body.h"
#include "fs/backend/sd.h"   /* route the byte write through the SD backend */

#include <errno.h>
#include <unistd.h>

ngx_int_t
webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len, off_t offset)
{
    brix_sd_obj_t obj;

    /* Positional write-full through the Storage Driver seam (syscall stays in
     * the backend); the caller passes the destination offset. */
    brix_sd_posix_wrap(&obj, fd);
    while (len > 0) {
        ssize_t nwritten;

        nwritten = obj.driver->pwrite(&obj, buf, len, offset);
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
        offset += nwritten;
    }

    return NGX_OK;
}

/**
 * WHAT: Copy a spooled temp file body to the final destination using zero-copy
 * copy_file_range() on Linux, falling back to pread+write on other platforms.
 *
 * Transfers bytes from buf->file (the spooled PUT temp file) to dst_fd (the final
 * WebDAV resource) in chunks. On Linux with SYS_copy_file_range support this uses
 * kernel-level zero-copy transfer; otherwise falls back to userspace pread+write loop.
 * Returns NGX_OK on complete copy or NGX_ERROR on any failure. The scratch buffer is
 * allocated lazily if needed for the fallback path.
 *
 * WHY: Spooled PUT writes (where the request body is stored in a temp file first) need
 * to be moved to their final destination after authentication and validation succeed.
 * copy_file_range() on Linux provides zero-copy kernel-level transfer without userspace
 * buffering — this is significantly faster for large files (>1MB) and avoids allocating
 * temporary buffers. The fallback path uses pread(2) + webdav_write_full(2) which works
 * on all platforms but has higher CPU overhead due to copying through user-space buffers.
 * This function handles multiple error conditions: EXDEV (cross-device copy not supported),
 * EOPNOTSUPP/ENOSYS (syscall unavailable), and retries only EINTR.
 *
 * HOW: Four-phase algorithm. Phase 1: validate source buf has valid file pointer and fd,
 * compute remaining bytes from buf->file_last - buf->file_pos. Phase 2 (Linux only): loop
 * using copy_file_range() syscall in WEBDAV_PUT_COPY_CHUNK-sized chunks — successful copies
 * decrement remaining, EINTR retries, non-recoverable errors return immediately, EXDEV/
 * ENOSYS/EOPNOTSUPP/EINVAL/EPERM break out to fallback. Phase 3 (fallback): allocate scratch
 * buffer via ngx_palloc(r->pool) if not already done, loop using pread + webdav_write_full.
 * Phase 4: return NGX_OK if remaining == 0 after either phase. Logging uses
 * brix_log_safe_path() for safe path formatting in error messages.
 */
ngx_int_t
webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd, ngx_buf_t *buf,
                          const char *path, u_char **scratch)
{
    off_t dst_off = 0;

    (void) scratch;
    return brix_http_body_write_buf(r, dst_fd, buf, &dst_off, path);
}

void
webdav_fadvise_willneed(ngx_log_t *log, ngx_fd_t fd, off_t offset, size_t len)
{
#if defined(POSIX_FADV_WILLNEED)
    int rc;

    if (fd == NGX_INVALID_FILE || len == 0) {
        return;
    }

    rc = posix_fadvise(fd, offset, (off_t) len, POSIX_FADV_WILLNEED);
    if (rc != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "brix_webdav: POSIX_FADV_WILLNEED ignored: %s",
                       strerror(rc));
    }
#else
    (void) log;
    (void) fd;
    (void) offset;
    (void) len;
#endif
}
