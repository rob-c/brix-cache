#include "cache_internal.h"
#include "../connection/netconnect.h"   /* shared outbound connect/I/O hardening */


#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ---- xrootd_cache_origin_close — teardown origin TCP/TLS connection ----
 *
 * WHAT: Releases all resources held by an origin connection struct. Frees SSL/SSL_CTX,
 *       closes the socket fd, and nullifies all pointers to prevent use-after-free.
 *
 * WHY: Called on every error path after a failed fetch attempt. Must be symmetric with
 *      origin_connect — every allocated resource must be freed regardless of success/failure.
 *      Order matters: SSL shutdown before free, SSL_CTX before fd close, fd last to avoid
 *      dangling references in the SSL layer. */

/* ---- xrootd_cache_origin_connect_addr — DNS resolve + connect + TLS handshake ----
 *
 * WHAT: Resolves host/port via getaddrinfo, iterates addrinfo results trying each socket,
 *       connects with non-blocking poll timeout (avoids ~2min TCP retransmit stall), sets
 *       SO_RCVTIMEO/SO_SNDTIMEO, then optionally performs TLS handshake with CA verification.
 *
 * WHY: Cache fill runs in a thread-pool worker that blocks. Unlike the event-loop main
 *      thread which uses epoll, this function must handle connect completion via poll().
 *      The poll timeout (XROOTD_CACHE_IO_TIMEOUT) prevents unreachable peers from holding
 *      the thread indefinitely. SO_RCVTIMEO/SO_SNDTIMEO bound all subsequent read/write.
 *      TLS is optional — if cache_origin_tls is set, creates SSL_CTX with CA verification,
 *      allocates SSL object, sets SNI hostname, and performs SSL_connect(). */

/* ---- xrootd_cache_origin_connect — thin wrapper for origin connect ----
 *
 * WHAT: Convenience function that calls origin_connect_addr using the configured origin
 *       host/port from conf. Returns 0 on success (connected + TLS if configured), -1 on error.
 *
 * WHY: Separates address resolution/connect logic from fill_t configuration access so that
 *      callers without a full xrootd_cache_fill_t can connect to arbitrary hosts/ports. */
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

int
xrootd_cache_origin_connect_addr(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const ngx_str_t *host, uint16_t portnum)
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

    if (host == NULL || host->len == 0 || host->data == NULL
        || portnum == 0)
    {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin address not configured");
        return -1;
    }

    snprintf(port, sizeof(port), "%u", (unsigned) portnum);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo((char *) host->data, port, &hints, &res) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin DNS resolution failed");
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        int            fd;

        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        xrootd_apply_socket_io_timeouts(fd, XROOTD_CACHE_IO_TIMEOUT);

        if (xrootd_connect_fd_deadline(fd, rp->ai_addr, rp->ai_addrlen,
                                       XROOTD_CACHE_IO_TIMEOUT * 1000) == 0)
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

        (void) SSL_set_tlsext_host_name(oc->ssl, (char *) host->data);
        SSL_set_fd(oc->ssl, oc->fd);

        if (SSL_connect(oc->ssl) != 1) {
            xrootd_cache_set_error(t, kXR_TLSRequired, 0,
                                   "cache origin TLS handshake failed");
            return -1;
        }
    }

    return 0;
}

int
xrootd_cache_origin_connect(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc)
{
    return xrootd_cache_origin_connect_addr(t, oc,
                                            &t->conf->cache_origin_host,
                                            t->conf->cache_origin_port);
}

