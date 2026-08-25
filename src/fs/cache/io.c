#include "cache_internal.h"
#include "fs/backend/sd.h"   /* route cache-content byte writes through the SD backend */


#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

/* cache_io_xfer — the one blocking full-transfer loop shared by both wire
 * directions (send and recv drifted apart as separate copies; the TPC plane
 * made the same extraction in tpc/outbound/io_xfer.c, whose loop is NOT
 * reusable here: it treats SSL WANT_READ/WANT_WRITE as hard failures and maps
 * no errno). Moves all `len` bytes over SSL or plain TCP, retrying the same
 * chunk on WANT_READ/WANT_WRITE/EINTR; other errors map to EIO/-1, and a
 * zero-length TCP transfer maps to `eof_errno` (EPIPE writing, ECONNRESET
 * reading). `sending` never writes through `p`. Safe to block: runs in a fill
 * thread-pool worker, not the event loop. */
static int
cache_io_xfer(brix_cache_origin_conn_t *oc, u_char *p, size_t len,
    int sending, int eof_errno)
{
    while (len > 0) {
        ssize_t n;

        if (oc->ssl != NULL) {
            n = sending ? SSL_write(oc->ssl, p, (int) len)
                        : SSL_read(oc->ssl, p, (int) len);
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

        n = sending ? send(oc->fd, p, len, 0) : recv(oc->fd, p, len, 0);
        if (n > 0) {
            p += (size_t) n;
            len -= (size_t) n;
            continue;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        if (n == 0) {
            errno = eof_errno;
        }

        return -1;
    }

    return 0;
}

/* brix_cache_io_send — blocking send of all len bytes to the origin (SSL or
 * plain TCP); a zero-length TCP write → EPIPE. The const is dropped only to
 * reach the shared loop, which never writes in the send direction. */

int
brix_cache_io_send(brix_cache_origin_conn_t *oc, const void *buf,
    size_t len)
{
    return cache_io_xfer(oc, (u_char *) (uintptr_t) buf, len, 1, EPIPE);
}

/* brix_cache_io_recv_exact — blocking recv of exactly len bytes from the origin
 * (SSL or plain TCP; the XRootD wire uses fixed-size headers); a zero-length
 * TCP read → ECONNRESET. */

int
brix_cache_io_recv_exact(brix_cache_origin_conn_t *oc, void *buf,
    size_t len)
{
    return cache_io_xfer(oc, buf, len, 0, ECONNRESET);
}

/* brix_cache_fd_write_all — blocking write of all len bytes to a local fd (the
 * fill worker draining origin data into the .part file before the atomic rename):
 * loops over partial writes, retries EINTR, -1 on any other error. */

int
brix_cache_fd_write_all(int fd, const void *buf, size_t len, off_t offset)
{
    const u_char   *p;
    brix_sd_obj_t obj;

    /* Route the cache-content byte write through the Storage Driver seam so the
     * syscall stays in the backend (positional pwrite; the caller passes the
     * running file offset). */
    brix_sd_posix_wrap(&obj, fd);
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

