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

int
brix_host_is_ipv6_literal(const char *host)
{
    return host != NULL && host[0] != '\0' && host[0] != '[' &&
           strchr(host, ':') != NULL;
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
