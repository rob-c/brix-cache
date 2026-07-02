#ifndef NGX_XROOTD_CONNECTION_NETCONNECT_H
#define NGX_XROOTD_CONNECTION_NETCONNECT_H

/*
 * netconnect.h — shared OUTBOUND connect/I/O hardening for blocking-thread paths.
 *
 * WHAT: two header-only helpers used by every subsystem that opens an outbound
 *   TCP connection from a worker thread (not the event loop):
 *     - xrootd_apply_socket_io_timeouts() — SO_RCVTIMEO + SO_SNDTIMEO on a fd.
 *     - xrootd_connect_fd_deadline()      — a non-blocking connect(2) bounded by
 *                                           poll(POLLOUT) + getsockopt(SO_ERROR).
 *
 * WHY: native TPC (src/tpc/connect.c), the read-through cache origin fill
 *   (src/cache/origin_connection.c) and OCSP fetching (src/crypto/ocsp.c) each
 *   grew their OWN copy of the same hardening dance, with the same Linux caveat:
 *   SO_SNDTIMEO does not reliably bound connect(2), so an unreachable/black-holed
 *   peer must be bounded with a non-blocking connect + poll() deadline or it stalls
 *   the worker thread for a full TCP retransmit window (~2 min). Factoring the
 *   shared logic here keeps ONE audited implementation across protocols and lets
 *   the raw-fd connectors (TPC, cache) drop their near-identical private copies.
 *
 * HOW: header-only `static ngx_inline`, compiled into each translation unit (the
 *   netopt.h precedent — no new .c, so the `config` source list is unchanged).
 *   Every setsockopt is best-effort/non-fatal; the connect helper restores the
 *   fd's original blocking mode on success and sets errno to the SO_ERROR cause on
 *   a connect-time failure. OpenSSL/BIO connectors keep their own connect path but
 *   can still share the I/O-timeout helper.
 */

#include <ngx_core.h>
#include <ngx_event.h>

#include "compat/af_policy.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>

/* Outcome of xrootd_resolve_connect_socket(), so the caller can emit its own
 * (protocol-specific) log message for each failure mode. */
typedef enum {
    XROOTD_RESOLVE_OK = 0,
    XROOTD_RESOLVE_ERR_DNS,     /* getaddrinfo() failed for host:port */
    XROOTD_RESOLVE_ERR_SOCKET   /* no resolved family yielded a usable socket */
} xrootd_resolve_status_t;

/*
 * Resolve host:port (SOCK_STREAM) and create the first non-blocking socket whose
 * address family succeeds; copy that sockaddr into *addr_out / *addrlen_out.
 * af_policy constrains getaddrinfo's family — XROOTD_AF_AUTO (AF_UNSPEC) tries all,
 * XROOTD_AF_INET / _INET6 force IPv4 / IPv6 only. Returns the connected-ready
 * socket fd (caller owns it) with
 * *status_out = XROOTD_RESOLVE_OK, or NGX_INVALID_FILE with *status_out set to
 * the failure reason (DNS vs no-usable-socket) so the caller logs its own
 * message. Does no logging itself and leaves no fd open on failure.
 *
 * Shared by the event-driven outbound connectors (proxy upstream, root://
 * upstream) which then wrap the fd in an nginx connection and connect() under
 * the event loop — so this helper deliberately stops at a non-blocking socket
 * + chosen address and does NOT call connect().
 */
static ngx_inline int
xrootd_resolve_connect_socket(const char *host, unsigned port,
    xrootd_af_policy_t af_policy,
    struct sockaddr_storage *addr_out, socklen_t *addrlen_out,
    xrootd_resolve_status_t *status_out)
{
    struct addrinfo  hints;
    struct addrinfo *res;
    struct addrinfo *rp;
    char             port_str[16];
    int              fd = (int) NGX_INVALID_FILE;

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = (int) af_policy;   /* AUTO==AF_UNSPEC keeps legacy behaviour */
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        *status_out = XROOTD_RESOLVE_ERR_DNS;
        return (int) NGX_INVALID_FILE;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = ngx_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == (int) NGX_INVALID_FILE) {
            continue;
        }
        if (ngx_nonblocking(fd) == NGX_ERROR) {
            ngx_close_socket(fd);
            fd = (int) NGX_INVALID_FILE;
            continue;
        }
        ngx_memcpy(addr_out, rp->ai_addr, rp->ai_addrlen);
        *addrlen_out = rp->ai_addrlen;
        break;
    }
    freeaddrinfo(res);

    if (fd == (int) NGX_INVALID_FILE) {
        *status_out = XROOTD_RESOLVE_ERR_SOCKET;
        return (int) NGX_INVALID_FILE;
    }

    *status_out = XROOTD_RESOLVE_OK;
    return fd;
}

/*
 * Apply SO_RCVTIMEO/SO_SNDTIMEO (timeout_secs seconds) to fd. Best-effort: a
 * denied/missing option is swallowed (never aborts a connection).
 */
static ngx_inline void
xrootd_apply_socket_io_timeouts(int fd, long timeout_secs)
{
    struct timeval tv;

    tv.tv_sec  = timeout_secs;
    tv.tv_usec = 0;
    (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/*
 * Connect fd to addr with an explicit poll() deadline (timeout_ms), so an
 * unreachable peer cannot stall the calling thread for a full TCP retransmit
 * window — SO_SNDTIMEO does not reliably bound connect(2) on Linux.
 *
 * Sets O_NONBLOCK, issues connect(2); on EINPROGRESS waits for POLLOUT up to
 * timeout_ms then checks SO_ERROR. Returns 0 on success (fd restored to its
 * original blocking mode), -1 on failure (on a connect-time failure errno is set
 * to the SO_ERROR cause). On the error paths the fd is left non-blocking — the
 * caller closes it on failure, so this is harmless.
 */
static ngx_inline int
xrootd_connect_fd_deadline(int fd, const struct sockaddr *addr,
    socklen_t addrlen, int timeout_ms)
{
    struct pollfd pfd;
    int           original_flags;
    int           rc;
    int           socket_error     = 0;
    socklen_t     socket_error_len = sizeof(socket_error);

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

    rc = poll(&pfd, 1, timeout_ms);
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

#endif /* NGX_XROOTD_CONNECTION_NETCONNECT_H */
