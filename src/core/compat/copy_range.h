/*
 * copy_range.h — shared copy_file_range(2) + pread/pwrite fallback helper.
 *
 * WHY: kXR_clone (read/clone.c) and kXR_chkpoint (write/chkpoint.c) each
 * contained an identical private static function implementing the same
 * algorithm: try copy_file_range(2) for kernel-side zero-copy, fall back to
 * pread/pwrite on ENOSYS / EOPNOTSUPP / EXDEV.  Centralising it here means
 * any fix, tuning, or security change applies everywhere automatically.
 */

#ifndef BRIX_COMPAT_COPY_RANGE_H
#define BRIX_COMPAT_COPY_RANGE_H

#include <ngx_core.h>
#include <sys/types.h>

/*
 * brix_copy_range — copy len bytes from src_fd at src_off to dst_fd at
 * dst_off using kernel-side copy_file_range(2) when available, falling back
 * to a pread/pwrite loop on ENOSYS, EOPNOTSUPP, or EXDEV (cross-device).
 *
 * src_path / dst_path are included in error log messages; pass NULL to omit.
 *
 * Returns NGX_OK on complete transfer, NGX_ERROR on failure (errno set).
 *
 * IMPORTANT: Blocking call — must not run on the nginx event-loop thread.
 * Invoke only from a thread-pool task or a post-accept worker context.
 */
ngx_int_t brix_copy_range(ngx_log_t *log,
                             int src_fd, off_t src_off,
                             int dst_fd, off_t dst_off,
                             size_t len,
                             const char *src_path, const char *dst_path);

#endif /* BRIX_COMPAT_COPY_RANGE_H */
