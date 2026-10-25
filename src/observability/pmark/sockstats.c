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
 * HOW: The PAL owns native socket counter layouts and RTT-unit conversion.
 *   Linux reads its append-only TCP_INFO ABI; Darwin uses TCP_CONNECTION_INFO.
 */

#include "pmark.h"
#include "platform/platform_api.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>

/* ---- Adapt native socket counters for Firefly ----
 * WHAT: Fill measured usage, returning NGX_DECLINED when the PAL cannot query it.
 * WHY: OS-specific layouts and scales must not leak into portable observation.
 * HOW: Zero the result, call the host adapter, translate only its return code.
 */
ngx_int_t
brix_pmark_sockstats(int fd, brix_pmark_sockstats_t *st)
{
    ngx_memzero(st, sizeof(*st));
    return brix_plat_tcp_stats(fd, &st->bytes_sent, &st->bytes_recv, &st->rtt_us)
           == 0 ? NGX_OK : NGX_DECLINED;
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

    /* Zero-init so ss_family is well-defined even if the kernel writes fewer
     * bytes than sizeof(ss) (analyzer-proven read of an indeterminate value
     * otherwise). */
    ngx_memzero(&ss, sizeof(ss));

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
