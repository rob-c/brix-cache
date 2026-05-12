#include "tpc_internal.h"

#if (NGX_THREADS)

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* SSRF guard: reject TPC connections to loopback or link-local addrs  */
/* ------------------------------------------------------------------ */

/*
 * Return 1 if the resolved address is prohibited under the current policy.
 *
 * allow_local:   if 0, block loopback (127/8, ::1) and link-local
 *                (169.254/16, fe80::/10).  Default policy: off.
 * allow_private: if 0, block RFC-1918 private ranges
 *                (10/8, 172.16/12, 192.168/16) and IPv6 ULA (fc00::/7).
 *                Default policy: on (allowed), because federation nodes
 *                commonly live on private networks.
 */
static int
tpc_ipv4_is_prohibited(uint32_t addr, ngx_flag_t allow_local,
    ngx_flag_t allow_private)
{
    if (!allow_local) {
        /* 127.0.0.0/8 */
        if ((addr >> 24) == 127) {
            return 1;
        }

        /* 169.254.0.0/16 */
        if ((addr >> 16) == 0xa9fe) {
            return 1;
        }
    }

    if (!allow_private) {
        /* 10.0.0.0/8 */
        if ((addr & 0xff000000u) == 0x0a000000u) {
            return 1;
        }

        /* 172.16.0.0/12 — must mask, not shift/compare nibble (172.16–172.31). */
        if ((addr & 0xfff00000u) == 0xac100000u) {
            return 1;
        }

        /* 192.168.0.0/16 */
        if ((addr & 0xffff0000u) == 0xc0a80000u) {
            return 1;
        }
    }

    return 0;
}


static int
tpc_ipv6_is_prohibited(const uint8_t *addr, ngx_flag_t allow_local,
    ngx_flag_t allow_private)
{
    if (!allow_local) {
        static const uint8_t loopback6[16] = {
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1
        };

        /* ::1 */
        if (ngx_memcmp(addr, loopback6, 16) == 0) {
            return 1;
        }

        /* fe80::/10 */
        if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80) {
            return 1;
        }
    }

    if (!allow_private) {
        /* fc00::/7 - IPv6 Unique Local Addresses */
        if ((addr[0] & 0xfe) == 0xfc) {
            return 1;
        }
    }

    return 0;
}


static int
tpc_addr_is_prohibited(const struct sockaddr *sa, ngx_flag_t allow_local,
    ngx_flag_t allow_private)
{
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
        uint32_t addr = ntohl(sin->sin_addr.s_addr);

        return tpc_ipv4_is_prohibited(addr, allow_local, allow_private);
    }

    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;

#if defined(IN6_IS_ADDR_V4MAPPED)
        /* ::ffff:x.x.x.x — classify using IPv4 SSRF rules */
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            uint32_t v4;

            v4 = ntohl(*(const uint32_t *) &sin6->sin6_addr.s6_addr[12]);
            return tpc_ipv4_is_prohibited(v4, allow_local, allow_private);
        }
#endif

        return tpc_ipv6_is_prohibited(sin6->sin6_addr.s6_addr,
                                      allow_local, allow_private);
    }

    return 0;
}


static int
tpc_wait_for_connect(int fd)
{
    struct pollfd pfd;
    int           rc;
    int           socket_error = 0;
    socklen_t     socket_error_len = sizeof(socket_error);

    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    rc = poll(&pfd, 1, TPC_CONNECT_TIMEOUT_SEC * 1000);
    if (rc <= 0) {
        return -1;
    }

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_len) != 0)
    {
        return -1;
    }

    return socket_error == 0 ? 0 : -1;
}


static int
tpc_connect_addr_with_timeout(int fd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    int original_flags;
    int rc;

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

    if (tpc_wait_for_connect(fd) != 0) {
        return -1;
    }

    (void) fcntl(fd, F_SETFL, original_flags);
    return 0;
}

/* ------------------------------------------------------------------ */
/* DNS resolution and TCP connect to TPC source server                   */
/* ------------------------------------------------------------------ */

int
tpc_connect(xrootd_tpc_pull_t *t)
{
    struct addrinfo  hints, *res, *rp;
    struct timeval   tv;
    char             port_str[16];
    int              fd = -1;
    uint16_t         src_port;

    src_port = t->src_port ? t->src_port : 1094;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned) src_port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(t->src_host, port_str, &hints, &res) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC DNS resolution failed for %s", t->src_host);
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (tpc_addr_is_prohibited(rp->ai_addr,
                                   t->conf->tpc_allow_local,
                                   t->conf->tpc_allow_private)) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC source host %s resolves to a prohibited address; "
                     "rejecting (tpc_allow_local=%d tpc_allow_private=%d)",
                     t->src_host,
                     (int) t->conf->tpc_allow_local,
                     (int) t->conf->tpc_allow_private);
            freeaddrinfo(res);
            return -1;
        }

        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        tv.tv_sec  = TPC_IO_TIMEOUT_SEC;
        tv.tv_usec = 0;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (tpc_connect_addr_with_timeout(fd, rp->ai_addr, rp->ai_addrlen)
            == 0)
        {
            break;
        }

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC connect to %s failed", t->src_host);
        return -1;
    }

    return fd;
}


/*
 * SSRF preflight for kXR_open TPC destination path: validate the resolved
 * source addresses before creating the local destination file or returning an
 * open handle. Uses the same prohibited-address rules as tpc_connect() for
 * the first candidate addrinfo entry (matching that connect path).
 */
int
xrootd_tpc_check_src_policy(const char *src_host, uint16_t src_port,
    ngx_flag_t allow_local, ngx_flag_t allow_private,
    char *err_msg, size_t err_msg_sz)
{
    struct addrinfo  hints, *res, *rp;
    char             port_str[16];

    if (src_host == NULL || src_host[0] == '\0') {
        snprintf(err_msg, err_msg_sz, "TPC source host missing");
        return -1;
    }

    if (src_port == 0) {
        src_port = 1094;
    }
    snprintf(port_str, sizeof(port_str), "%u", (unsigned) src_port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(src_host, port_str, &hints, &res) != 0) {
        snprintf(err_msg, err_msg_sz,
                 "TPC DNS resolution failed for %s", src_host);
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (tpc_addr_is_prohibited(rp->ai_addr, allow_local,
                                   allow_private)) {
            snprintf(err_msg, err_msg_sz,
                     "TPC source host %s resolves to a prohibited address; "
                     "rejecting (tpc_allow_local=%d tpc_allow_private=%d)",
                     src_host,
                     (int) allow_local,
                     (int) allow_private);
            freeaddrinfo(res);
            return -1;
        }
        /* address is allowed — continue checking remaining entries */
    }

    freeaddrinfo(res);
    return 0;
}

#endif /* NGX_THREADS */
