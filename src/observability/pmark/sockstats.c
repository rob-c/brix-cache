/*
 * sockstats.c — socket statistics + time/address formatting for firefly.
 *
 * WHAT: Three small helpers the firefly emitter needs that have no existing
 *   reuse point in the tree: (1) read a connected socket's transferred-byte and
 *   RTT counters from the kernel (TCP_INFO), (2) render "now" as the firefly
 *   microsecond UTC timestamp, and (3) render a socket end's IP + port as
 *   strings with the SciTags address-family indicator.
 *
 * WHY: XRootD's firefly carries usage.received/sent (from TCP_INFO), netlink.rtt,
 *   and flow-id.{src,dst}-ip/port.  The codebase's brix_format_iso8601() only
 *   emits millisecond ".000Z" precision, and there is no sockaddr→"ip:port"
 *   helper, so firefly needs its own.  All three are best-effort: on any failure
 *   they zero/blank the output and return NGX_DECLINED — packet marking never
 *   fails a transfer.
 *
 * HOW: TCP_INFO is read into a RAW buffer and the needed fields are pulled by
 *   their fixed kernel-ABI byte offsets.  glibc's <netinet/tcp.h> struct tcp_info
 *   is a frozen subset that lacks tcpi_bytes_acked/received, and the kernel's
 *   <linux/tcp.h> struct conflicts with it, so neither struct can be used
 *   directly — the offset read is the portable approach (the same one `ss` uses).
 *   The kernel tcp_info layout is append-only and stable across versions.
 */

#include "pmark.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>

#if defined(__linux__)
#include <netinet/tcp.h>     /* TCP_INFO constant only (not struct tcp_info) */

/* Fixed offsets into the kernel `struct tcp_info` (bytes).  8-byte u8 preamble,
 * then 24 u32 fields (tcpi_rtt is the 16th, at 8 + 15*4 = 68), then 8-aligned
 * u64 fields: pacing_rate(104), max_pacing_rate(112), bytes_acked(120),
 * bytes_received(128). */
#define PMARK_TCPI_OFF_RTT             68
#define PMARK_TCPI_OFF_BYTES_ACKED     120
#define PMARK_TCPI_OFF_BYTES_RECEIVED  128
#endif


ngx_int_t
brix_pmark_sockstats(int fd, brix_pmark_sockstats_t *st)
{
    ngx_memzero(st, sizeof(*st));

#if defined(__linux__)
    {
        unsigned char  buf[256];
        socklen_t      len = sizeof(buf);
        uint32_t       rtt;
        uint64_t       acked, recvd;

        if (fd < 0
            || getsockopt(fd, IPPROTO_TCP, TCP_INFO, buf, &len) != 0)
        {
            return NGX_DECLINED;
        }

        if (len >= PMARK_TCPI_OFF_RTT + sizeof(rtt)) {
            ngx_memcpy(&rtt, buf + PMARK_TCPI_OFF_RTT, sizeof(rtt));
            st->rtt_us = rtt;
        }
        if (len >= PMARK_TCPI_OFF_BYTES_RECEIVED + sizeof(recvd)) {
            ngx_memcpy(&acked, buf + PMARK_TCPI_OFF_BYTES_ACKED, sizeof(acked));
            ngx_memcpy(&recvd, buf + PMARK_TCPI_OFF_BYTES_RECEIVED,
                       sizeof(recvd));
            st->bytes_sent = acked;
            st->bytes_recv = recvd;
        }
        return NGX_OK;
    }
#else
    (void) fd;
    return NGX_DECLINED;
#endif
}


void
brix_pmark_iso8601_now(char *buf, size_t buflen)
{
    struct timeval  tv;
    struct tm       tm;

    if (buflen == 0) {
        return;
    }
    buf[0] = '\0';

    if (gettimeofday(&tv, NULL) != 0 || gmtime_r(&tv.tv_sec, &tm) == NULL) {
        return;
    }

    /* yyyy-mm-ddThh:mm:ss.uuuuuu+00:00 — the scitags firefly format. */
    (void) snprintf(buf, buflen,
        "%04d-%02d-%02dT%02d:%02d:%02d.%06ld+00:00",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec, (long) tv.tv_usec);
}


ngx_int_t
brix_pmark_endpoint(int fd, int which, char *ip, size_t iplen, int *port,
    char *afi)
{
    struct sockaddr_storage  ss;
    socklen_t                len = sizeof(ss);
    int                      rc;

    if (iplen) {
        ip[0] = '\0';
    }
    *port = 0;
    *afi  = '4';

    if (fd < 0) {
        return NGX_DECLINED;
    }

    rc = which == 0 ? getpeername(fd, (struct sockaddr *) &ss, &len)
                    : getsockname(fd, (struct sockaddr *) &ss, &len);
    if (rc != 0) {
        return NGX_DECLINED;
    }

    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
        *port = ntohs(sin->sin_port);
        *afi  = '4';
        return inet_ntop(AF_INET, &sin->sin_addr, ip, (socklen_t) iplen)
               ? NGX_OK : NGX_DECLINED;
    }

    if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
        *port = ntohs(sin6->sin6_port);

        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            /* ::ffff:a.b.c.d — report as plain IPv4 (matches XRootD afi). */
            struct in_addr v4;
            ngx_memcpy(&v4, sin6->sin6_addr.s6_addr + 12, sizeof(v4));
            *afi = '4';
            return inet_ntop(AF_INET, &v4, ip, (socklen_t) iplen)
                   ? NGX_OK : NGX_DECLINED;
        }

        *afi = '6';
        return inet_ntop(AF_INET6, &sin6->sin6_addr, ip, (socklen_t) iplen)
               ? NGX_OK : NGX_DECLINED;
    }

    return NGX_DECLINED;
}
