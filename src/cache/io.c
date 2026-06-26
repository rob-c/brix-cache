#include "cache_internal.h"
#include "../fs/backend/sd.h"   /* route cache-content byte writes through the SD backend */


#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- xrootd_cache_io_send — send all bytes over socket/TLS ----
 *
 * WHAT: Blocking send helper that writes len bytes to the origin connection.
 *       Handles both SSL and plain TCP sockets, retries on WANT_READ/WANT_WRITE/EINTR.
 *
 * WHY: Cache fill operations run in nginx thread pool (blocking context). Unlike
 *      the event-loop main thread, this function can block indefinitely waiting for
 *      network bytes — it must handle SSL renegotiation states and partial writes.
 *
 * HOW: Iterates remaining bytes with send/SSL_write loop. On WANT_READ/WANT_WRITE:
 *      continues without advancing pointer (retry same chunk). On other errors:
 *      maps to EIO and returns -1. Zero-length write on TCP → errno=EPIPE. */

int
xrootd_cache_io_send(xrootd_cache_origin_conn_t *oc, const void *buf,
    size_t len)
{
    const u_char *p;

    p = buf;
    while (len > 0) {
        ssize_t n;

        if (oc->ssl != NULL) {
            n = SSL_write(oc->ssl, p, (int) len);
            if (n > 0) {
                p += (size_t) n;
                len -= (size_t) n;
                continue;
            }

            switch (SSL_get_error(oc->ssl, (int) n)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                errno = EIO;
                return -1;
            }
        }

        n = send(oc->fd, p, len, 0);
        if (n > 0) {
            p += (size_t) n;
            len -= (size_t) n;
            continue;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        if (n == 0) {
            errno = EPIPE;
        }

        return -1;
    }

    return 0;
}

/* ---- xrootd_cache_io_recv_exact — receive exact byte count from socket/TLS ----
 *
 * WHAT: Blocking recv helper that reads exactly len bytes from the origin connection.
 *       Handles both SSL and plain TCP sockets, retries on WANT_READ/WANT_WRITE/EINTR.
 *
 * WHY: Cache fill operations require exact-length wire protocol messages (XRootD
 *      headers are fixed-size). Unlike event-loop recv which accumulates incrementally,
 *      this function guarantees exactly len bytes — partial reads loop until complete.
 *
 * HOW: Iterates remaining bytes with recv/SSL_read loop. On WANT_READ/WANT_WRITE:
 *      continues without advancing pointer (retry same chunk). On other errors:
 *      maps to EIO and returns -1. Zero-length read on TCP → errno=ECONNRESET. */

int
xrootd_cache_io_recv_exact(xrootd_cache_origin_conn_t *oc, void *buf,
    size_t len)
{
    u_char *p;

    p = buf;
    while (len > 0) {
        ssize_t n;

        if (oc->ssl != NULL) {
            n = SSL_read(oc->ssl, p, (int) len);
            if (n > 0) {
                p += (size_t) n;
                len -= (size_t) n;
                continue;
            }

            switch (SSL_get_error(oc->ssl, (int) n)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                errno = EIO;
                return -1;
            }
        }

        n = recv(oc->fd, p, len, 0);
        if (n > 0) {
            p += (size_t) n;
            len -= (size_t) n;
            continue;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        if (n == 0) {
            errno = ECONNRESET;
        }

        return -1;
    }

    return 0;
}

/* ---- xrootd_cache_fd_write_all — write all bytes to local file descriptor ----
 *
 * WHAT: Blocking fd write helper that writes len bytes to a local file descriptor.
 *       Retries on EINTR, returns -1 on any other error (including zero-length write).
 *
 * WHY: Cache fill worker thread writes received origin data to a local .part temp
 *      file before atomic rename. Must guarantee all bytes land on disk — partial
 *      writes loop until complete. Used only within NGX_THREADS build. */

int
xrootd_cache_fd_write_all(int fd, const void *buf, size_t len, off_t offset)
{
    const u_char   *p;
    xrootd_sd_obj_t obj;

    /* Route the cache-content byte write through the Storage Driver seam so the
     * syscall stays in the backend (positional pwrite; the caller passes the
     * running file offset). */
    xrootd_sd_posix_wrap(&obj, fd);
    p = buf;
    while (len > 0) {
        ssize_t n;

        n = obj.driver->pwrite(&obj, p, len, offset);
        if (n > 0) {
            p += (size_t) n;
            len -= (size_t) n;
            offset += n;
            continue;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        return -1;
    }

    return 0;
}

