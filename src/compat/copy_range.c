/*
 * copy_range.c — shared copy_file_range(2) + pread/pwrite fallback.
 *
 * WHY: kXR_clone (read/clone.c) and kXR_chkpoint (write/chkpoint.c) each
 * contained an identical private static function implementing the same
 * two-phase copy algorithm.  Centralising it here means a fix or tuning
 * (e.g. new fallback errno, larger buffer, EINTR handling) applies to
 * both callers automatically.
 *
 * HOW: Two-phase loop.
 *   Phase 1 (Linux only): syscall(__NR_copy_file_range) loop until len == 0
 *     or a non-recoverable error; EXDEV / ENOSYS / EOPNOTSUPP / EINVAL / EPERM
 *     jump to phase 2.
 *   Phase 2 (fallback): pread from src_off, pwrite to dst_off in 256 KB chunks.
 *     256 KB matches clone.c's CLONE_COPY_BUF - large enough for HEP file
 *     transfers without excessive stack usage.
 */

#include "copy_range.h"
#include "../fs/backend/sd.h"   /* phase-55: route raw fd I/O through the SD seam */

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#if defined(__linux__) && defined(__NR_copy_file_range)
#include <sys/syscall.h>
#endif

/* 256 KB fallback buffer — matches CLONE_COPY_BUF in read/clone.c. */
#define XROOTD_COPY_RANGE_BUFSZ  (256 * 1024)

/* ---- xrootd_copy_range_fallback — portable pread/pwrite copy of [src_off, +len) ----
 *
 * WHAT: Copies `len` bytes from src_fd@src_off to dst_fd@dst_off in 256 KB
 * chunks using pread/pwrite. Returns NGX_OK on full copy, NGX_ERROR (errno set
 * and logged) on I/O failure or unexpected EOF/short write.
 *
 * WHY: Phase-2 of xrootd_copy_range — used both when copy_file_range(2) is not
 * compiled in and when it returns a recoverable error mid-copy. Extracted into
 * its own function so the two callers share one implementation and the caller
 * stays a flat, goto-free control flow.
 *
 * HOW: Outer loop pread()s up to one buffer; inner loop pwrite()s it fully,
 * retrying EINTR; advances src_off/dst_off/len until len reaches 0.
 */
static ngx_int_t
xrootd_copy_range_fallback(ngx_log_t *log, int src_fd, off_t src_off,
    int dst_fd, off_t dst_off, size_t len,
    const char *src_path, const char *dst_path)
{
    u_char          buf[XROOTD_COPY_RANGE_BUFSZ];
    xrootd_sd_obj_t src_obj, dst_obj;

    /* Route both raw syscalls through the Storage Driver seam (phase-55). */
    xrootd_sd_posix_wrap(&src_obj, src_fd);
    xrootd_sd_posix_wrap(&dst_obj, dst_fd);

    while (len > 0) {
        size_t  want = (len < sizeof(buf)) ? len : sizeof(buf);
        ssize_t nr   = xrootd_sd_posix_driver.pread(&src_obj, buf, want, src_off);
        ssize_t nread;
        u_char *p;

        if (nr < 0) {
            if (errno == EINTR) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: copy_range pread failed %s",
                          src_path ? src_path : "-");
            return NGX_ERROR;
        }

        if (nr == 0) {
            errno = EIO;
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd: copy_range pread unexpected EOF %s",
                          src_path ? src_path : "-");
            return NGX_ERROR;
        }

        nread = nr;
        p = buf;
        while (nr > 0) {
            ssize_t nw = xrootd_sd_posix_driver.pwrite(&dst_obj, p, (size_t) nr, dst_off);
            if (nw < 0) {
                if (errno == EINTR) {
                    continue;
                }
                ngx_log_error(NGX_LOG_ERR, log, errno,
                              "xrootd: copy_range pwrite failed %s",
                              dst_path ? dst_path : "-");
                return NGX_ERROR;
            }

            if (nw == 0) {
                errno = EIO;
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "xrootd: copy_range pwrite wrote zero bytes %s",
                              dst_path ? dst_path : "-");
                return NGX_ERROR;
            }

            p       += nw;
            dst_off += (off_t) nw;
            nr      -= nw;
            len     -= (size_t) nw;
        }

        src_off += (off_t) nread;
    }

    return NGX_OK;
}

ngx_int_t
xrootd_copy_range(ngx_log_t *log,
                  int src_fd, off_t src_off,
                  int dst_fd, off_t dst_off,
                  size_t len,
                  const char *src_path, const char *dst_path)
{
#if defined(__linux__) && defined(__NR_copy_file_range)
    xrootd_sd_obj_t src_obj, dst_obj;

    /* Route the zero-copy primitive through the Storage Driver seam (phase-55);
     * the loop and the pread/pwrite fallback stay here in the VFS. */
    xrootd_sd_posix_wrap(&src_obj, src_fd);
    xrootd_sd_posix_wrap(&dst_obj, dst_fd);

    while (len > 0) {
        size_t  want = (len > (size_t) SSIZE_MAX) ? (size_t) SSIZE_MAX : len;
        ssize_t n  = xrootd_sd_posix_driver.copy_range(&src_obj, src_off,
                                                       &dst_obj, dst_off, want);
        if (n > 0) {
            src_off += (off_t) n;
            dst_off += (off_t) n;
            len     -= (size_t) n;
            continue;
        }

        if (n == 0) {
            errno = EIO;
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd: copy_file_range unexpected EOF %s -> %s",
                          src_path ? src_path : "-",
                          dst_path ? dst_path : "-");
            return NGX_ERROR;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno == EXDEV || errno == ENOSYS || errno == EOPNOTSUPP
            || errno == EINVAL || errno == EPERM)
        {
            /* copy_file_range unsupported for this fd pair / range — finish the
             * remaining bytes with the portable pread/pwrite path. */
            return xrootd_copy_range_fallback(log, src_fd, src_off,
                                              dst_fd, dst_off, len,
                                              src_path, dst_path);
        }

        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: copy_file_range failed %s -> %s",
                      src_path ? src_path : "-",
                      dst_path ? dst_path : "-");
        return NGX_ERROR;
    }
    return NGX_OK;
#endif

    /* copy_file_range(2) not available at build time — use the portable path. */
    return xrootd_copy_range_fallback(log, src_fd, src_off,
                                      dst_fd, dst_off, len,
                                      src_path, dst_path);
}
