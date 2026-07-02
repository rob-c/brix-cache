/*
 * host_split.c — parse "host[:port]" / "[ipv6][:port]" (see host_split.h).
 *
 * The bracketed-IPv6-aware authority parser the native client reimplements in
 * several places. ngx-free; libc only.
 */
#include "host_split.h"

#include <string.h>
#include <stdlib.h>

int
xrootd_split_host_port(const char *in, char *host, size_t hsz, int *port,
                       int default_port)
{
    if (in == NULL || host == NULL || hsz == 0 || port == NULL) {
        return -1;
    }

    /* Bracketed IPv6 literal: "[::1]" or "[::1]:port" — the brackets disambiguate
     * the address colons from the port colon, and are stripped from `host`. */
    if (in[0] == '[') {
        const char *rb = strchr(in, ']');
        size_t      hlen;
        if (rb == NULL) {
            return -1;   /* unterminated literal */
        }
        hlen = (size_t) (rb - in - 1);
        if (hlen == 0 || hlen >= hsz) {
            return -1;
        }
        memcpy(host, in + 1, hlen);
        host[hlen] = '\0';
        if (rb[1] == ':') {
            int p = atoi(rb + 2);
            if (p <= 0 || p > 65535) {
                return -1;
            }
            *port = p;
        } else if (rb[1] == '\0') {
            *port = default_port;
        } else {
            return -1;   /* junk after ']' */
        }
        return 0;
    }

    {
        const char *colon = strrchr(in, ':');
        if (colon != NULL) {
            size_t hlen = (size_t) (colon - in);
            int    p;
            if (hlen == 0 || hlen >= hsz) {
                return -1;
            }
            memcpy(host, in, hlen);
            host[hlen] = '\0';
            p = atoi(colon + 1);
            if (p <= 0 || p > 65535) {
                return -1;
            }
            *port = p;
        } else {
            size_t hlen = strlen(in);
            if (hlen == 0 || hlen >= hsz) {
                return -1;
            }
            memcpy(host, in, hlen);
            host[hlen] = '\0';
            *port = default_port;
        }
        return 0;
    }
}
