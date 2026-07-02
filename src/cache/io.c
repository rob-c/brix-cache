#include "cache_internal.h"
#include "fs/backend/sd.h"   /* route cache-content byte writes through the SD backend */


#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

/* xrootd_cache_io_send — blocking send of all len bytes to the origin (SSL or plain
 * TCP), retrying the same chunk on WANT_READ/WANT_WRITE/EINTR; other errors map to
 * EIO/-1 (a zero-length TCP write → EPIPE). Safe to block: runs in a fill
 * thread-pool worker, not the event loop. */

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

/* xrootd_cache_io_recv_exact — blocking recv of exactly len bytes from the origin
 * (SSL or plain TCP), looping over partial reads and retrying on
 * WANT_READ/WANT_WRITE/EINTR (the XRootD wire uses fixed-size headers); other errors
 * map to EIO/-1 (a zero-length TCP read → ECONNRESET). Fill thread-pool worker only. */

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

/* xrootd_cache_fd_write_all — blocking write of all len bytes to a local fd (the
 * fill worker draining origin data into the .part file before the atomic rename):
 * loops over partial writes, retries EINTR, -1 on any other error. */

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

