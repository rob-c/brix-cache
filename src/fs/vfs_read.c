/*
 * vfs_read.c — the shared full-read primitive.
 *
 * WHAT: Implements xrootd_vfs_pread_full(), the EINTR-safe, short-read-tolerant
 *       pread loop used throughout the VFS (the I/O core in vfs_io_core.c and the
 *       per-buffer write copier, plus the AIO offload bodies).
 *
 * WHY:  Every VFS read has to apply the same short-read/EINTR retry policy, and
 *       every data byte has to traverse the Storage Driver seam rather than a raw
 *       syscall. Concentrating the loop here guarantees both, once.
 *
 * HOW:  xrootd_vfs_pread_full() wraps the fd in a POSIX storage-driver object and
 *       drives driver.pread() in a loop until len bytes are read or EOF, retrying
 *       on EINTR and reporting the byte count in *nread even on error.
 */
#include "vfs_internal.h"
#include "backend/sd.h"

/* EINTR-safe, short-read-tolerant pread into buf. Loops until len bytes are
 * read or EOF; *nread (if non-NULL) reports the byte count even on error. */
ngx_int_t
xrootd_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len,
    off_t offset, size_t *nread)
{
    size_t          done = 0;
    xrootd_sd_obj_t obj;

    /* Route every data byte read through the Storage Driver seam (phase-55); the
     * EINTR/short-read loop policy stays here in the VFS. Keeping the syscall in
     * the backend (src/fs/backend/) — never raw here — is the invariant: a
     * non-POSIX driver (block/object) slots in without touching the VFS. (This
     * deliberately reverts the phase-56 A-1 micro-optimization, which inlined a
     * raw pread at the cost of putting data POSIX in the VFS layer.) */
    xrootd_sd_posix_wrap(&obj, fd);

    while (done < len) {
        ssize_t n = xrootd_sd_posix_driver.pread(&obj, buf + done, len - done,
                                                 offset + (off_t) done);

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
