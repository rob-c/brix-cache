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
#include "fs/backend/sd.h"   /* copy_file_range fast path via the SD driver */
#include "fs/vfs/vfs.h"          /* brix_vfs_pread_full / pwrite_full */

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#if defined(__linux__) && defined(__NR_copy_file_range)
#include <sys/syscall.h>
#endif

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

#if defined(__linux__) && defined(__NR_copy_file_range)

/* brix_cfr_errno_recoverable — is a copy_file_range errno finishable by fallback
 * WHAT: Returns 1 when `err` is one of the errnos that mean copy_file_range is
 * unsupported for this fd pair or range (EXDEV, ENOSYS, EOPNOTSUPP, EINVAL,
 * EPERM) and the copy can still complete via the portable pread/pwrite path;
 * returns 0 otherwise (a genuine I/O failure).
 *
 * WHY: The recoverable-errno set is the single decision that separates a
 * fall-back-and-continue from a hard error. Naming it keeps the phase-1 loop's
 * control flow flat and the exact errno list reviewable in one place.
 *
 * HOW: A single boolean over the five sanctioned errnos.
 */
static int
brix_cfr_errno_recoverable(int err)
{
    return err == EXDEV || err == ENOSYS || err == EOPNOTSUPP
           || err == EINVAL || err == EPERM;
}

/* brix_copy_range_cfr — phase-1 copy_file_range(2) loop over the SD seam
 * WHAT: Copies the range via the object's own driver copy_range vtable until
 * `*len` reaches 0. Returns NGX_OK on full copy, NGX_ERROR (errno set + logged)
 * on unexpected EOF or a genuine failure, or NGX_AGAIN when copy_file_range is
 * unsupported mid-copy — in which case the src_off, dst_off and len out-params are left pointing
 * at the remaining bytes for the caller's fallback.
 *
 * WHY: Isolating the zero-copy loop keeps brix_copy_range a flat two-line
 * dispatch and confines the Linux-only, errno-branching logic to one place that
 * updates the running offsets/length in step so the fallback can resume exactly
 * where the fast path stopped.
 *
 * HOW: 1) Wrap both bare fds as stack POSIX SD objects. 2) Each iteration clamps
 * `want` to SSIZE_MAX and calls the driver copy_range. 3) n>0 advances the
 * offsets/length; n==0 is a premature EOF (EIO) and fails; EINTR retries; a
 * recoverable errno returns NGX_AGAIN with the remaining range; any other errno
 * is logged and fails.
 */
static ngx_int_t
brix_copy_range_cfr(ngx_log_t *log, int src_fd, off_t *src_off,
    int dst_fd, off_t *dst_off, size_t *len,
    const char *src_path, const char *dst_path)
{
    brix_sd_obj_t src_obj, dst_obj;

    /* Route the zero-copy primitive through the Storage Driver seam; dispatch via
     * the object's own driver vtable (backend-agnostic) rather than the hardcoded
     * POSIX driver. The pread/pwrite fallback composes the VFS primitives. */
    brix_sd_posix_wrap(&src_obj, src_fd);
    brix_sd_posix_wrap(&dst_obj, dst_fd);

    while (*len > 0) {
        size_t  want = (*len > (size_t) SSIZE_MAX) ? (size_t) SSIZE_MAX : *len;
        ssize_t n  = src_obj.driver->copy_range(&src_obj, *src_off,
                                                &dst_obj, *dst_off, want);
        if (n > 0) {
            *src_off += (off_t) n;
            *dst_off += (off_t) n;
            *len     -= (size_t) n;
            continue;
        }

        if (n == 0) {
            errno = EIO;
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "brix: copy_file_range unexpected EOF %s -> %s",
                          src_path ? src_path : "-",
                          dst_path ? dst_path : "-");
            return NGX_ERROR;
        }

        if (errno == EINTR) {
            continue;
        }

        if (brix_cfr_errno_recoverable(errno)) {
            /* copy_file_range unsupported for this fd pair / range — signal the
             * caller to finish the remaining bytes with the portable path. */
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "brix: copy_file_range failed %s -> %s",
                      src_path ? src_path : "-",
                      dst_path ? dst_path : "-");
        return NGX_ERROR;
    }
    return NGX_OK;
}

#endif /* __linux__ && __NR_copy_file_range */

ngx_int_t
brix_copy_range(ngx_log_t *log,
                  int src_fd, off_t src_off,
                  int dst_fd, off_t dst_off,
                  size_t len,
                  const char *src_path, const char *dst_path)
{
#if defined(__linux__) && defined(__NR_copy_file_range)
    /* Fast path first; NGX_AGAIN means copy_file_range gave out mid-copy and
     * src_off/dst_off/len now mark the remainder to finish via the portable
     * path (falls through to the shared fallback return below). */
    ngx_int_t rc = brix_copy_range_cfr(log, src_fd, &src_off,
                                       dst_fd, &dst_off, &len,
                                       src_path, dst_path);
    if (rc != NGX_AGAIN) {
        return rc;
    }
#endif

    /* copy_file_range(2) unavailable at build time, or unsupported for this fd
     * pair / range at run time — use the portable pread/pwrite path. */
    return brix_copy_range_fallback(log, src_fd, src_off,
                                      dst_fd, dst_off, len,
                                      src_path, dst_path);
}
