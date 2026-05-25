/*
 * io.h — shared blocking write helper: xrootd_write_full().
 *
 * Used by the WebDAV PUT handler and the S3 PUT handler so the
 * EINTR-retry loop lives in one place.  Compiled once (as part of the
 * stream module) and linked into all modules via the shared nginx binary.
 */

#ifndef XROOTD_COMPAT_IO_H
#define XROOTD_COMPAT_IO_H

#include <ngx_core.h>

/*
 * xrootd_write_full — write exactly len bytes from buf to fd.
 *
 * Wraps write(2) in a loop that retries on EINTR until all bytes are
 * transferred.  Any other error or a zero-byte write (unexpected short
 * write treated as EIO) returns NGX_ERROR with errno set by the kernel.
 * Returns NGX_OK on complete transfer.
 *
 * IMPORTANT: This is a blocking synchronous call.  It must only be
 * invoked from a thread-pool task or a path that is known not to run
 * on the nginx event-loop thread.
 */
ngx_int_t xrootd_write_full(ngx_fd_t fd, u_char *buf, size_t len);

#endif /* XROOTD_COMPAT_IO_H */
