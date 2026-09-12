/*
 * copy_range.c — platform-abstracted copy_file_range(2) + pread/pwrite fallback.
 * 
 * MIGRATED to use platform API (Phase 3). Original implementation preserved
 * in src/platform/linux/copy_range.c and src/platform/darwin/copy_range.c.
 *
 * WHY: kXR_clone (read/clone.c) and kXR_chkpoint (write/chkpoint.c) each
 * contained an identical private static function implementing the same
 * two-phase copy algorithm.  Centralising it here means a fix or tuning
 * (e.g. new fallback errno, larger buffer, EINTR handling) applies to
 * both callers automatically.
 *
 * HOW: Two-phase loop.
 *   Phase 1 (Linux only): brix_platform_copy_range() uses copy_file_range
 *   Phase 2 (fallback): pread from src_off, pwrite to dst_off in 256 KB chunks.
 *     256 KB matches clone.c's CLONE_COPY_BUF - large enough for HEP file
 *     transfers without excessive stack usage.
 */

#include "copy_range.h"
#include "fs/backend/sd.h"
#include "fs/vfs/vfs.h"
#include "platform/platform_api.h"  /* Platform abstraction for copy operations */

#include <errno.h>
#include <limits.h>
#include <unistd.h>

/* 256 KB fallback buffer — matches CLONE_COPY_BUF in read/clone.c. */
#define BRIX_COPY_RANGE_BUFSZ  (256 * 1024)

/* brix_copy_range_fallback — portable pread/pwrite copy of [src_off, +len)
 * WHAT: Copies `len` bytes from src_fd@src_off to dst_fd@dst_off in 256 KB
 * chunks using pread/pwrite. Returns NGX_OK on full copy, NGX_ERROR (errno set
 * and logged) on I/O failure or unexpected EOF/short write.
 *
 * WHY: Phase-2 of brix_copy_range — used both when copy_file_range(2) is not
 * compiled in and when it returns a recoverable error mid-copy. Extracted into
 * its own function so the two callers share one implementation and the caller
 * stays a flat, goto-free control flow.
 *
 * HOW: Outer loop fills one buffer via brix_vfs_pread_full (EINTR + short-read
 * handled by the primitive); a partial fill below `want` is a premature EOF and
 * fails; brix_vfs_pwrite_full writes the buffer fully. Advances
 * src_off/dst_off/len until len reaches 0.
 */
static ngx_int_t
brix_copy_range_fallback(ngx_log_t *log, int src_fd, off_t src_off,
    int dst_fd, off_t dst_off, size_t len,
    const char *src_path, const char *dst_path)
{
    u_char buf[BRIX_COPY_RANGE_BUFSZ];

    while (len > 0) {
        size_t want = (len < sizeof(buf)) ? len : sizeof(buf);
        size_t got  = 0;

        /* pread_full loops over EINTR/short reads through the storage seam,
         * filling `want` bytes unless the source ends early. */
        if (brix_vfs_pread_full(src_fd, buf, want, src_off, &got) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "brix: copy_range pread failed %s",
                          src_path ? src_path : "-");
            return NGX_ERROR;
        }

        /* A short fill means EOF before `len` bytes — the source is smaller than
         * the requested range, which is a hard error for a fixed-length copy. */
        if (got < want) {
            errno = EIO;
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "brix: copy_range pread unexpected EOF %s",
                          src_path ? src_path : "-");
            return NGX_ERROR;
        }

        if (brix_vfs_pwrite_full(dst_fd, buf, got, dst_off) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "brix: copy_range pwrite failed %s",
                          dst_path ? dst_path : "-");
            return NGX_ERROR;
        }

        src_off += (off_t) got;
        dst_off += (off_t) got;
        len     -= got;
    }

    return NGX_OK;
}

/* brix_copy_range — copy [src_off, +len) to dst_fd@dst_off with fallback
 * WHAT: Copies `len` bytes from src_fd@src_off to dst_fd@dst_off using
 * copy_file_range(2) on Linux, falling back to pread/pwrite on error or macOS.
 * Returns NGX_OK on full copy, NGX_ERROR on failure (errno set and logged).
 *
 * WHY: Unified copy interface that works across platforms. On Linux, uses the
 * efficient copy_file_range(2) syscall when available; on macOS or when the
 * syscall fails with a recoverable error, falls back to portable pread/pwrite.
 *
 * HOW: Call brix_platform_copy_range() which handles platform differences.
 * If it returns -1 with a recoverable errno, use the fallback path.
 */
ngx_int_t
brix_copy_range(ngx_log_t *log, int src_fd, off_t src_off,
    int dst_fd, off_t dst_off, size_t len,
    const char *src_path, const char *dst_path)
{
    off_t src_off_copy = src_off;
    off_t dst_off_copy = dst_off;
    ssize_t copied;
    
    /* Try platform-native copy (copy_file_range on Linux, pread/pwrite on macOS) */
    copied = brix_platform_copy_range(src_fd, &src_off_copy, dst_fd, &dst_off_copy, len, 0);
    
    if (copied >= 0 && (size_t)copied == len) {
        /* Full copy succeeded */
        return NGX_OK;
    }
    
    /* Partial copy or error - check if we should retry with fallback */
    if (copied > 0) {
        /* Some bytes copied - adjust parameters and continue with fallback */
        src_off = src_off_copy;
        dst_off = dst_off_copy;
        len -= (size_t)copied;
    }
    
    /* Check if error is recoverable (should use fallback) */
    /* On Linux, copy_file_range may fail with EXDEV, ENOSYS, EOPNOTSUPP, etc. */
    /* On macOS, brix_platform_copy_range already uses pread/pwrite */
    
    /* Fall back to pread/pwrite for remaining bytes */
    return brix_copy_range_fallback(log, src_fd, src_off, dst_fd, dst_off, len,
                                    src_path, dst_path);
}
