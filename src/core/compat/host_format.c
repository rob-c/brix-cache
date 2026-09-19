/*
 * host_format.c — see host_format.h.
 *
 * Bracket-on-emit for IPv6 literal hosts.  The module stores hosts canonically
 * bare (ngx_sock_ntop(...,0) for captured peers, ngx_parse_url which strips the
 * brackets off "[::1]" input, getnameinfo(NI_NUMERICHOST) for resolved pins);
 * these helpers re-bracket only at the point a host is written into a host:port
 * wire string, HTTP Host: header, or rebuilt root:// URL.  Mirrors the format
 * already used at src/read/locate.c (AF_INET6 locate branch: "S%c[%s]:%d").
 */

#include "host_format.h"

#include <string.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/in.h>

int
brix_host_is_ipv6_literal(const char *host)
{
    return host != NULL && host[0] != '\0' && host[0] != '[' &&
           strchr(host, ':') != NULL;
}


/* ---- brix_host_unmap_v4 ----
 *
 * WHAT: "::ffff:10.0.0.1" -> "10.0.0.1"; anything else copied unchanged.
 * WHY : See the header — the mapped literal is the form a stock XrdCl puts in
 *       tpc.src for an IPv4 source, and it matches no IPv4 iPAddress SAN.
 * HOW : Only a string containing ':' can be a v6 literal, so the cheap test
 *       gates the parse. inet_pton is the discriminator proper: it accepts the
 *       whole grammar and nothing else, which no prefix comparison on "::ffff:"
 *       can claim (that prefix is also the start of "::ffff:1:2", a perfectly
 *       ordinary address whose low 32 bits are not an IPv4 host). The V4MAPPED
 *       test then keeps the fold to the exactly-equivalent case, and the low
 *       four bytes are the address itself — inet_ntop spells them back out.
 */
int
brix_host_unmap_v4(const char *host, char *out, size_t sz)
{
    struct in6_addr  a6;
    struct in_addr   a4;
    int              n;

    if (out == NULL || sz == 0) {
        return 0;
    }
    if (host == NULL) {
        out[0] = '\0';
        return 0;
    }

    if (strchr(host, ':') != NULL
        && inet_pton(AF_INET6, host, &a6) == 1
        && IN6_IS_ADDR_V4MAPPED(&a6))
    {
        memcpy(&a4, &a6.s6_addr[12], sizeof(a4));
        if (inet_ntop(AF_INET, &a4, out, (socklen_t) sz) != NULL) {
            return 1;
        }
        out[0] = '\0';
        return 0;
    }

    n = snprintf(out, sz, "%s", host);
    if (n < 0 || (size_t) n >= sz) {
        out[0] = '\0';
        return 0;
    }
    return 1;
}

size_t
brix_format_host(const char *host, char *out, size_t sz)
{
    int n;

    if (out == NULL || sz == 0) {
        return 0;
    }
    if (host == NULL) {
        out[0] = '\0';
        return 0;
    }

    if (brix_host_is_ipv6_literal(host)) {
        n = snprintf(out, sz, "[%s]", host);
    } else {
        n = snprintf(out, sz, "%s", host);
    }

    /* Truncation (n >= sz) leaves a partial string — reject it so callers never
     * emit a malformed half-bracketed host; out stays a valid empty string. */
    if (n < 0 || (size_t) n >= sz) {
        out[0] = '\0';
        return 0;
    }
    return (size_t) n;
}

size_t
brix_format_host_port(const char *host, uint16_t port, char *out, size_t sz)
{
    int n;

    if (out == NULL || sz == 0) {
        return 0;
    }
    if (host == NULL) {
        out[0] = '\0';
        return 0;
    }

    if (brix_host_is_ipv6_literal(host)) {
        n = snprintf(out, sz, "[%s]:%u", host, (unsigned) port);
    } else {
        n = snprintf(out, sz, "%s:%u", host, (unsigned) port);
    }

    if (n < 0 || (size_t) n >= sz) {
        out[0] = '\0';
        return 0;
    }
    return (size_t) n;
}
