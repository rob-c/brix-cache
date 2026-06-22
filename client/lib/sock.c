/*
 * sock.c — blocking TCP with poll(2) deadlines.
 *
 * WHAT: connect-with-timeout (happy-path v4/v6 via getaddrinfo) plus full-read /
 *       full-write helpers that bound each syscall with poll(2).
 * WHY:  The client is deliberately synchronous (no nginx event loop, no XrdCl
 *       PostMaster); poll gives us per-operation timeouts without going async.
 * HOW:  The socket is non-blocking only during connect (so we can time it out),
 *       then switched back to blocking; reads/writes poll first, then do the
 *       blocking syscall, looping on partial transfers and EINTR.
 */
#include "xrdc.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

static int
set_blocking(int fd, int blocking)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    return fcntl(fd, F_SETFL, flags);
}

/*
 * Apply latency + liveness socket options (best-effort; failures are ignored).
 * TCP_NODELAY kills Nagle so small request frames go out immediately (matters on a
 * pipelined, high-RTT link). SO_KEEPALIVE + the keep* triad let the OS notice a
 * silently-dead peer (the "wifi vanished" case) as a backstop to the app-level
 * kXR_ping heartbeat. Tunables are conservative so a brief stall is not mistaken
 * for a dead peer.
 */
void
xrdc_sock_tune(int fd)
{
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
#ifdef TCP_KEEPIDLE
    int idle = 30, intvl = 10, cnt = 3;   /* ~60s to declare a dead peer */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

/*
 * Per-candidate connect cap (ms). When more resolved addresses remain to try,
 * a single attempt is bounded by this so a black-holed family (the classic
 * broken-IPv6-on-dual-stack case) yields quickly to the next family instead of
 * burning the caller's full (30s) budget on a dead address — RFC 8305 Happy
 * Eyeballs in spirit, sequential rather than racing. The FINAL candidate always
 * gets the full timeout, so a single-address host's semantics are unchanged and
 * a merely-slow (not dead) sole path is never abandoned early.
 */
#define XRDC_CONNECT_ATTEMPT_MS 5000

/*
 * Open one connected, tuned, blocking socket to a single resolved address.
 * Returns the fd on success, or -1 on any failure (socket / connect / timeout) —
 * the caller simply walks to the next candidate. The socket is non-blocking only
 * for the connect (so poll(2) can time it out), then switched back to blocking.
 * timeout_ms bounds the EINPROGRESS settle.
 */
static int
connect_one(const struct addrinfo *ai, int timeout_ms)
{
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        return -1;
    }
    if (set_blocking(fd, 0) < 0) {
        close(fd);
        return -1;
    }

    /* connect()==0 means it settled immediately; only EINPROGRESS needs poll. */
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }

        struct pollfd pfd;
        int           pr;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        do {
            pr = poll(&pfd, 1, timeout_ms);
        } while (pr < 0 && errno == EINTR);
        if (pr <= 0) {
            int e = (pr == 0) ? ETIMEDOUT : errno;   /* timeout vs poll error */
            close(fd);
            errno = e;            /* report the real cause (close may clobber) */
            return -1;
        }

        int       err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) {
            close(fd);
            return -1;
        }
        if (err != 0) {
            close(fd);
            errno = err;          /* propagate SO_ERROR (ECONNREFUSED/…) so callers
                                   * can distinguish a definitive refusal from a stall */
            return -1;
        }
    }

    if (set_blocking(fd, 1) < 0) {
        close(fd);
        return -1;
    }
    xrdc_sock_tune(fd);   /* TCP_NODELAY + keepalive (best-effort) */
    return fd;
}

/*
 * Address family (AF_INET / AF_INET6) of a connected socket, via getsockname;
 * AF_UNSPEC if unknown. Lets a wire error be attributed to the right family so
 * only an IPv6 failure trips the downgrade.
 */
static int
fd_family(int fd)
{
    struct sockaddr_storage ss;
    socklen_t               sl = sizeof(ss);
    if (fd < 0 || getsockname(fd, (struct sockaddr *) &ss, &sl) != 0) {
        return AF_UNSPEC;
    }
    return ss.ss_family;
}

/*
 * Resolve host with the given family hint and connect to the first candidate
 * that answers (happy-eyeballs, bounded per non-final attempt). On a working
 * IPv4 reached only after an IPv6 candidate failed, demote the session to
 * IPv4-only (the connect-time trigger). Returns the fd, or -1 with *st set.
 */
static int
connect_resolved(const char *host, int port, int timeout_ms, int family,
                 xrdc_status *st)
{
    struct addrinfo  hints, *res = NULL, *ai;
    char             portstr[16];
    int              gai;
    int              v6_failed = 0;   /* an IPv6 candidate failed this resolve */
    int              last_errno = 0;  /* real errno of the last failed candidate */

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);

    gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) {
        xrdc_status_set(st, XRDC_ESOCK, 0, "resolve %s:%d: %s",
                        host, port, gai_strerror(gai));
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        /* Bound a non-final attempt so a dead family yields promptly; the last
         * candidate keeps the full budget (see XRDC_CONNECT_ATTEMPT_MS). */
        int attempt_ms =
            (ai->ai_next != NULL && timeout_ms > XRDC_CONNECT_ATTEMPT_MS)
            ? XRDC_CONNECT_ATTEMPT_MS : timeout_ms;
        int fd = connect_one(ai, attempt_ms);

        if (fd >= 0) {
            if (ai->ai_family == AF_INET && v6_failed) {
                xrdc_netpref_demote_ipv6(host);
            }
            freeaddrinfo(res);
            return fd;
        }
        last_errno = errno;   /* capture before the next attempt / freeaddrinfo clobbers it */
        if (ai->ai_family == AF_INET6) {
            v6_failed = 1;
        }
    }

    freeaddrinfo(res);
    xrdc_status_set(st, XRDC_ESOCK, last_errno, "connect %s:%d failed", host, port);
    return -1;
}

int
xrdc_tcp_connect(const char *host, int port, int timeout_ms, xrdc_status *st)
{
    /* AF_UNSPEC normally; AF_INET once this session has demoted to IPv4-only
     * (netpref.c) — either because an IPv6 connect failed where IPv4 worked, or
     * because an established IPv6 connection failed over the wire. Demotion makes
     * the resolver omit v6 records, so no further v6 connect timeout is paid. */
    int family = xrdc_netpref_family();
    int fd = connect_resolved(host, port, timeout_ms, family, st);

    /* Self-heal: we are demoted to IPv4-only but IPv4 will not connect here (no
     * A record, or v4 refused/timed out). That happens if a transient IPv6 wire
     * error optimistically demoted what is really an IPv6-only host. Revert to
     * dual-stack and retry so the connection still comes up. */
    if (fd < 0 && family == AF_INET) {
        xrdc_netpref_undo_demote("the IPv4-only path failed");
        fd = connect_resolved(host, port, timeout_ms, AF_UNSPEC, st);
    }
    return fd;
}

static int
plain_read_full(xrdc_io *io, void *buf, size_t n, xrdc_status *st)
{
    int      fd         = io->fd;
    int      timeout_ms = io->timeout_ms;
    uint8_t *p          = (uint8_t *) buf;
    size_t   got        = 0;

    while (got < n) {
        struct pollfd pfd;
        ssize_t       r;
        int           pr;

        pfd.fd = fd;
        pfd.events = POLLIN;
        do {
            /* Phase 40 (a): observe a cooperative cancel even when blocked on a
             * stalled peer — a SIGINT interrupts poll (EINTR), and the next pass
             * bails promptly instead of silently re-arming for the full timeout. */
            if (xrdc_copy_quit_requested()) {
                xrdc_status_set(st, XRDC_ESOCK, EINTR,
                                "transfer cancelled (signal)");
                return -1;
            }
            pr = poll(&pfd, 1, timeout_ms);
        } while (pr < 0 && errno == EINTR);

        if (pr == 0) {
            xrdc_status_set(st, XRDC_ESOCK, ETIMEDOUT, "read timed out");
            return -1;
        }
        if (pr < 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "poll(read): %s", strerror(errno));
            return -1;
        }

        r = read(fd, p + got, n - got);
        if (r == 0) {
            xrdc_status_set(st, XRDC_ESOCK, 0,
                            "connection closed by peer (read %zu/%zu)", got, n);
            return -1;
        }
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            xrdc_status_set(st, XRDC_ESOCK, errno, "read: %s", strerror(errno));
            return -1;
        }
        got += (size_t) r;
    }
    return 0;
}

static int
plain_write_full(xrdc_io *io, const void *buf, size_t n, xrdc_status *st)
{
    int            fd         = io->fd;
    int            timeout_ms = io->timeout_ms;
    const uint8_t *p          = (const uint8_t *) buf;
    size_t         sent       = 0;

    while (sent < n) {
        struct pollfd pfd;
        ssize_t       w;
        int           pr;

        pfd.fd = fd;
        pfd.events = POLLOUT;
        do {
            /* Phase 40 (a): prompt cooperative cancel (see xrdc_read_full). */
            if (xrdc_copy_quit_requested()) {
                xrdc_status_set(st, XRDC_ESOCK, EINTR,
                                "transfer cancelled (signal)");
                return -1;
            }
            pr = poll(&pfd, 1, timeout_ms);
        } while (pr < 0 && errno == EINTR);

        if (pr == 0) {
            xrdc_status_set(st, XRDC_ESOCK, ETIMEDOUT, "write timed out");
            return -1;
        }
        if (pr < 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "poll(write): %s", strerror(errno));
            return -1;
        }

        /* send() with MSG_NOSIGNAL: a write to a peer that has gone away returns
         * EPIPE instead of raising SIGPIPE, which would otherwise KILL a one-shot
         * tool (xrdcp) on a flaky/severed link. Treated as a normal transport
         * error so the caller's reconnect/retry logic handles it. */
        w = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            xrdc_status_set(st, XRDC_ESOCK, errno, "write: %s", strerror(errno));
            return -1;
        }
        sent += (size_t) w;
    }
    return 0;
}

/*
 * A transport failure (XRDC_ESOCK) that is NOT a user-driven cancel (EINTR) is
 * evidence the wire is bad; if this connection is IPv6 it trips the session-wide
 * IPv4 downgrade (netpref.c) so the reconnect comes back over IPv4. This is the
 * single chokepoint for both cleartext and TLS byte I/O, so it covers every
 * tool — root://, WebDAV, and S3 alike.
 */
static void
note_io_failure(xrdc_io *io, int rc, const xrdc_status *st)
{
    if (rc < 0 && st->kxr == XRDC_ESOCK && st->sys_errno != EINTR) {
        xrdc_netpref_note_wire_error(fd_family(io->fd));
    }
}

int
xrdc_read_full(xrdc_io *io, void *buf, size_t n, xrdc_status *st)
{
    int rc = (io->ssl != NULL) ? xrdc_tls_read(io, buf, n, st)
                               : plain_read_full(io, buf, n, st);
    note_io_failure(io, rc, st);
    return rc;
}

int
xrdc_write_full(xrdc_io *io, const void *buf, size_t n, xrdc_status *st)
{
    int rc = (io->ssl != NULL) ? xrdc_tls_write(io, buf, n, st)
                               : plain_write_full(io, buf, n, st);
    note_io_failure(io, rc, st);
    return rc;
}
