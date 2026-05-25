/*
 * io.c - blocking file write helpers shared by PUT handlers.
 */

#include "webdav.h"
#include "../compat/http_body.h"
#include "../compat/io.h"

#include <unistd.h>

/**
 * WHAT: Write all bytes from buffer to file descriptor, retrying on EINTR.
 *
 * Performs a full write loop using sequential write(2) syscalls until len bytes are
 * transferred or an error occurs. Advances the file offset via sequential writes (not
 * pwrite(2)) so this function is suitable for PUT operations where the caller tracks
 * cumulative offsets across multiple chunks. Returns NGX_OK on complete transfer or
 * NGX_ERROR on any non-retryable failure (EINTR is retried).
 *
 * WHY: Sequential writes are used instead of pwrite because WebDAV PUT handlers write
 * to a single destination file in order, advancing the offset naturally. This avoids
 * the overhead of tracking absolute offsets per syscall and matches nginx's streaming
 * write pattern. EINTR retry loop handles signal interruption during long writes —
 * common on servers under high load or when other threads/signals are active. The
 * nwritten == 0 check catches short reads that indicate EOF unexpectedly (should never
 * happen for a write to an open file unless the filesystem is corrupted).
 *
 * HOW: Three-step loop. Step 1: call write(fd, buf, len) with remaining bytes. Step 2:
 * handle result — negative means error (EINTR = retry, other = return NGX_ERROR), zero
 * means unexpected EOF (errno=EIO + NGX_ERROR). Step 3: advance buffer pointer and
 * decrement length by nwritten bytes. Loop continues until len reaches 0 (success) or
 * an unretryable error occurs. No logging on failure — callers add context-specific log
 * messages via xrootd_log_safe_path(). Uses raw write(2) syscall, not
 * nginx's event-loop abstraction, because this is a blocking synchronous operation for
 * PUT body transfer (handled by thread pool or direct execution).
 */
/*
 * webdav_write_full — thin wrapper around the shared xrootd_write_full().
 *
 * Preserved as a named entry point for WebDAV callers (put.c,
 * fs/copy_engine.c) so their call sites need no change.  The actual
 * EINTR-retry loop lives in src/compat/io.c.
 */
ngx_int_t
webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len)
{
    return xrootd_write_full(fd, buf, len);
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
 * xrootd_log_safe_path() for safe path formatting in error messages.
 */
ngx_int_t
webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd, ngx_buf_t *buf,
                          const char *path, u_char **scratch)
{
    off_t dst_off = 0;

    (void) scratch;
    return xrootd_http_body_write_buf(r, dst_fd, buf, &dst_off, path);
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
                       "xrootd_webdav: POSIX_FADV_WILLNEED ignored: %s",
                       strerror(rc));
    }
#else
    (void) log;
    (void) fd;
    (void) offset;
    (void) len;
#endif
}
