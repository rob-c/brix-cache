#include "cache_internal.h"

#if (NGX_THREADS)

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

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

int
xrootd_cache_fd_write_all(int fd, const void *buf, size_t len)
{
    const u_char *p;

    p = buf;
    while (len > 0) {
        ssize_t n;

        n = write(fd, p, len);
        if (n > 0) {
            p += (size_t) n;
            len -= (size_t) n;
            continue;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        return -1;
    }

    return 0;
}

#endif /* NGX_THREADS */
