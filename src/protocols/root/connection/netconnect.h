#ifndef NGX_BRIX_CONNECTION_NETCONNECT_H
#define NGX_BRIX_CONNECTION_NETCONNECT_H

/*
 * netconnect.h — shared OUTBOUND connect/I/O hardening for blocking-thread paths.
 *
 * WHAT: two header-only helpers used by every subsystem that opens an outbound
 *   TCP connection from a worker thread (not the event loop):
 *     - brix_apply_socket_io_timeouts() — SO_RCVTIMEO + SO_SNDTIMEO on a fd.
 *     - brix_connect_fd_deadline()      — a non-blocking connect(2) bounded by
 *                                           poll(POLLOUT) + getsockopt(SO_ERROR).
 *
 * WHY: native TPC (src/tpc/outbound/connect.c), the read-through cache origin fill
 *   (src/fs/cache/origin_connection.c) and OCSP fetching (src/auth/crypto/
 *   ocsp_transport.c) each grew their OWN copy of the same hardening dance, with
 *   the same Linux caveat:
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
 *   can still share the I/O-timeout helper.  Name resolution is NOT here: every
 *   connector resolves through src/net/dns (brix_dns_resolve() on the event loop,
 *   brix_dns_resolve_sync() on a worker thread — phase-116), so this header knows
 *   only sockaddrs.
 */

#include <ngx_core.h>
#include <ngx_event.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>

/*
 * Apply SO_RCVTIMEO/SO_SNDTIMEO (timeout_secs seconds) to fd. Best-effort: a
 * denied/missing option is swallowed (never aborts a connection).
 */
static ngx_inline void
brix_apply_socket_io_timeouts(int fd, long timeout_secs)
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
brix_connect_fd_deadline(int fd, const struct sockaddr *addr,
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

#endif /* NGX_BRIX_CONNECTION_NETCONNECT_H */
