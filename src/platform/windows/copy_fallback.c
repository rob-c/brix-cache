/* Windows transfer fallbacks: buffered fd copies and unsupported splice.
 * CopyFile2, kernel range copy and TransmitFile remain in copy_range.c.
 */
#include "copy_internal.h"
#if BRIX_PLATFORM_WINDOWS
#include <errno.h>
#include <io.h>
#include <stdio.h>

/* ---- Seek an explicitly nonzero copy offset ----
 * WHAT: Return zero or the CRT seek failure.
 * WHY: Both sides retain the existing optional-offset contract.
 * HOW: 1. Leave absent/zero offsets alone. 2. Seek an explicit offset.
 */
static int
brix_win32_seek_copy_offset(int fd, const off_t *offset)
{
    if (offset == NULL || *offset == 0) {
        return 0;
    }
    return _lseeki64(fd, *offset, SEEK_SET) < 0 ? -1 : 0;
}

/* ---- Write one copy buffer with the existing interrupt retry ----
 * WHAT: Return the CRT write result, retrying one interrupted write.
 * WHY: Keep write-error handling separate from read/offset accounting.
 * HOW: 1. Write the buffer. 2. Retry once only when interrupted.
 */
static ssize_t
brix_win32_write_copy_buffer(int fd, const char *buffer, size_t length)
{
    ssize_t written = _write(fd, buffer, (unsigned int)length);
    if (written < 0 && errno == EINTR) {
        return _write(fd, buffer, (unsigned int)length);
    }
    return written;
}
/**
 * brix_win32_buffered_copy - Fallback buffered copy implementation
 *
 * @in_fd: Input file descriptor
 * @in_off: Input offset (or NULL)
 * @out_fd: Output file descriptor
 * @out_off: Output offset (or NULL)
 * @len: Bytes to copy
 * @return: Bytes copied on success, -1 on error
 *
 * This is the universal fallback when CopyFile2 and FSCTL_COPY_FILE_RANGE
 * are not available. Uses a 64KB buffer for reasonable performance.
 */
ssize_t
brix_win32_buffered_copy(int in_fd, off_t *in_off,
                         int out_fd, off_t *out_off,
                         size_t len)
{
    char buffer[65536];  /* 64KB buffer */
    size_t remaining = len;
    ssize_t total_copied = 0;

    /* Seek to input offset if provided */
    if (brix_win32_seek_copy_offset(in_fd, in_off) < 0) {
        return -1;
    }

    /* Seek to output offset if provided */
    if (brix_win32_seek_copy_offset(out_fd, out_off) < 0) {
        return -1;
    }

    while (remaining > 0) {
        size_t to_read = (remaining > sizeof(buffer)) ? sizeof(buffer) : remaining;
        ssize_t bytes_read = _read(in_fd, buffer, (unsigned int)to_read);

        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;  /* Retry on interrupt */
            }
            return (total_copied > 0) ? total_copied : -1;
        }

        if (bytes_read == 0) {
            /* EOF reached */
            break;
        }

        ssize_t bytes_written = brix_win32_write_copy_buffer(
            out_fd, buffer, (size_t)bytes_read);
        if (bytes_written < 0) {
            return (total_copied > 0) ? total_copied : -1;
        }

        total_copied += bytes_written;
        remaining -= bytes_read;
    }

    /* Update offsets if provided */
    if (in_off != NULL) {
        *in_off += total_copied;
    }
    if (out_off != NULL) {
        *out_off += total_copied;
    }

    return total_copied;
}

/* ==========================================================================
 * SPLICE IMPLEMENTATION (STUB)
 * ========================================================================== */

/**
 * brix_plat_splice - Zero-copy pipe splice (Linux-specific)
 *
 * @in_fd: Input file descriptor
 * @out_fd: Output file descriptor (must be pipe on Linux)
 * @nbytes: Bytes to splice
 * @flags: Splice flags (BRIX_SPLICE_F_*)
 * @return: Bytes spliced on success, -1 on error (errno set)
 *
 * Windows Implementation:
 * STUB - Returns ENOSYS (function not implemented)
 *
 * Rationale:
 * - splice() is a Linux-specific syscall for moving data between
 *   file descriptors using a pipe as an intermediary
 * - Windows has no equivalent mechanism
 * - Use TransmitFile for file->socket or buffered copy for other cases
 *
 * Alternatives on Windows:
 * 1. brix_plat_sendfile() - for file->socket transfers
 * 2. brix_plat_copy_range() - for file->file transfers
 * 3. IOCP - for async I/O operations
 * 4. Manual buffered copy - universal fallback
 */
ssize_t
brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags)
{
    (void)in_fd;
    (void)out_fd;
    (void)nbytes;
    (void)flags;

    errno = ENOSYS;  /* Function not implemented */
    return -1;
}

#endif /* BRIX_PLATFORM_WINDOWS */
