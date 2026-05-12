#include "cache_internal.h"

#if (NGX_THREADS)

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

void
xrootd_cache_origin_close(xrootd_cache_origin_conn_t *oc)
{
    if (oc->ssl != NULL) {
        SSL_shutdown(oc->ssl);
        SSL_free(oc->ssl);
        oc->ssl = NULL;
    }

    if (oc->ssl_ctx != NULL) {
        SSL_CTX_free(oc->ssl_ctx);
        oc->ssl_ctx = NULL;
    }

    if (oc->fd >= 0) {
        close(oc->fd);
        oc->fd = -1;
    }
}

/*
 * Non-blocking connect with an explicit poll timeout so that an unreachable
 * IPv6 (or IPv4) peer cannot stall the thread for a full TCP retransmit
 * interval (up to ~2 minutes).  SO_SNDTIMEO does not reliably bound
 * connect(2) on Linux.
 */
static int
cache_connect_with_timeout(int fd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    struct pollfd  pfd;
    int            original_flags;
    int            rc;
    int            socket_error     = 0;
    socklen_t      socket_error_len = sizeof(socket_error);

    original_flags = fcntl(fd, F_GETFL, 0);
    if (original_flags < 0) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) != 0) {
        return -1;
    }

    rc = connect(fd, addr, addrlen);
    if (rc == 0) {
        (void) fcntl(fd, F_SETFL, original_flags);
        return 0;
    }

    if (errno != EINPROGRESS) {
        return -1;
    }

    pfd.fd      = fd;
    pfd.events  = POLLOUT;
    pfd.revents = 0;

    rc = poll(&pfd, 1, XROOTD_CACHE_IO_TIMEOUT * 1000);
    if (rc <= 0) {
        return -1;
    }

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_len) != 0)
    {
        return -1;
    }

    if (socket_error != 0) {
        errno = socket_error;
        return -1;
    }

    (void) fcntl(fd, F_SETFL, original_flags);
    return 0;
}


int
xrootd_cache_origin_connect(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc)
{
    struct addrinfo  hints;
    struct addrinfo *res, *rp;
    char             port[16];
    int              rc;

    oc->fd = -1;
    oc->ssl_ctx = NULL;
    oc->ssl = NULL;
    res = NULL;
    rc = -1;

    snprintf(port, sizeof(port), "%u", (unsigned) t->conf->cache_origin_port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo((char *) t->conf->cache_origin_host.data, port,
                    &hints, &res) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin DNS resolution failed");
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        struct timeval tv;
        int            fd;

        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        tv.tv_sec  = XROOTD_CACHE_IO_TIMEOUT;
        tv.tv_usec = 0;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (cache_connect_with_timeout(fd, rp->ai_addr, rp->ai_addrlen)
            == 0)
        {
            oc->fd = fd;
            rc = 0;
            break;
        }

        close(fd);
    }

    freeaddrinfo(res);

    if (rc != 0) {
        xrootd_cache_set_syserror(t, kXR_ServerError,
                                  "cache origin connect failed");
        return -1;
    }

    if (t->conf->cache_origin_tls) {
        oc->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (oc->ssl_ctx == NULL) {
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin TLS context failed");
            return -1;
        }

        SSL_CTX_set_verify(oc->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (t->conf->trusted_ca.len > 0) {
            if (!SSL_CTX_load_verify_locations(oc->ssl_ctx,
                    (char *) t->conf->trusted_ca.data, NULL))
            {
                xrootd_cache_set_error(t, kXR_ServerError, 0,
                                       "cache origin CA load failed");
                return -1;
            }
        } else {
            (void) SSL_CTX_set_default_verify_paths(oc->ssl_ctx);
        }

        oc->ssl = SSL_new(oc->ssl_ctx);
        if (oc->ssl == NULL) {
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin TLS allocation failed");
            return -1;
        }

        (void) SSL_set_tlsext_host_name(oc->ssl,
                                        (char *) t->conf->cache_origin_host.data);
        SSL_set_fd(oc->ssl, oc->fd);

        if (SSL_connect(oc->ssl) != 1) {
            xrootd_cache_set_error(t, kXR_TLSRequired, 0,
                                   "cache origin TLS handshake failed");
            return -1;
        }
    }

    return 0;
}

#endif /* NGX_THREADS */
