/*
 * vfs_write.c — the shared full-write primitive.
 *
 * WHAT: Implements xrootd_vfs_pwrite_full(), the EINTR-safe / short-write-safe
 *       pwrite loop used across the VFS (the I/O core in vfs_io_core.c and the
 *       per-buffer copiers).
 *
 * WHY:  Every VFS write has to apply the same short-write/EINTR retry policy, and
 *       every data byte has to traverse the Storage Driver seam rather than a raw
 *       syscall. Concentrating the loop here guarantees both, once.
 *
 * HOW:  xrootd_vfs_pwrite_full() wraps the fd in a POSIX storage-driver object and
 *       drives driver.pwrite() in a loop until exactly len bytes are written,
 *       retrying on EINTR and treating a 0-byte pwrite as EIO.
 */
#include "vfs_internal.h"
#include "fs/backend/sd.h"

/* EINTR-safe, short-write-safe pwrite loop. Writes exactly len bytes at offset
 * or returns NGX_ERROR; a 0-byte pwrite is treated as EIO. */
ngx_int_t
xrootd_vfs_pwrite_full(ngx_fd_t fd, const u_char *buf, size_t len,
    off_t offset)
{
    size_t          done = 0;
    xrootd_sd_obj_t obj;

    /* Route every data byte write through the Storage Driver seam (phase-55); the
     * EINTR/short-write loop policy stays here in the VFS. The syscall lives in the
     * backend so a non-POSIX driver slots in unchanged. (Reverts phase-56 A-1.) */
    xrootd_sd_posix_wrap(&obj, fd);

    while (done < len) {
        ssize_t n = xrootd_sd_posix_driver.pwrite(&obj, buf + done, len - done,
                                                  offset + (off_t) done);

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
