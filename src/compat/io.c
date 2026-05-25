/*
 * io.c — shared blocking write helper used by WebDAV and S3 PUT handlers.
 *
 * Both handlers need an EINTR-retrying full-write loop.  This file
 * centralises that logic so any fix (e.g. EAGAIN handling, logging policy)
 * applies to all protocols automatically.
 */

#include "io.h"

#include <errno.h>
#include <unistd.h>

/*
 * WHAT: Write all len bytes from buf to fd, retrying on EINTR.
 *
 * HOW: Three-step loop.
 *   Step 1 — call write(fd, buf, len) with the remaining byte count.
 *   Step 2 — handle result: negative means error (EINTR → retry,
 *             any other errno → NGX_ERROR); zero means an unexpected
 *             short write (treated as EIO).
 *   Step 3 — advance buf pointer and reduce remaining length by the
 *             number of bytes written.  Loop until len reaches zero
 *             (success) or an unretryable error occurs.
 *
 * WHY: Sequential writes without pwrite(2) so that the file offset
 * advances naturally — callers (PUT handlers) write large bodies in
 * order without tracking absolute offsets per syscall.  No logging here:
 * callers add context-specific messages after checking the return code.
 */
ngx_int_t
xrootd_write_full(ngx_fd_t fd, u_char *buf, size_t len)
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
