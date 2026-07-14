/*
 * net_target.c — shared external transfer target parser and SSRF guard.
 *
 * See net_target.h for the public API.
 *
 * Address classification helpers (ipv4/ipv6 prohibited-range checks) were
 * extracted from src/tpc/outbound/connect.c so that WebDAV HTTP-TPC and future S3
 * remote-copy features share the same SSRF policy without reimplementing it.
 *
 * The URL grammar (net_target_parse.c) and the blocking DNS checkers
 * (net_target_dns.c) live in sibling translation units; this file holds the
 * address-classification chokepoint they both route through and the pre-DNS
 * host allowlist.
 */

#include "net_target.h"
#include "net_target_internal.h"
#include "cstr.h"

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>


/*
 * Return 1 if the IPv4 host-order address is prohibited under policy.
 *
 * Local (loopback + link-local) and private (RFC-1918) ranges are
 * controlled independently so callers can allow federation nodes on
 * private networks (common in HEP) while still blocking loopback.
 */
static int
net_ipv4_is_prohibited(uint32_t addr, ngx_flag_t allow_local,
    ngx_flag_t allow_private)
{
    if (!allow_local) {
        /* 127.0.0.0/8 */
        if ((addr >> 24) == 127) {
            return 1;
        }

        /* 169.254.0.0/16 — IPv4 link-local */
        if ((addr >> 16) == 0xa9fe) {
            return 1;
        }
    }

    if (!allow_private) {
        /* 10.0.0.0/8 */
        if ((addr & 0xff000000u) == 0x0a000000u) {
            return 1;
        }

        /* 172.16.0.0/12 — must mask, not shift/compare nibble (172.16–172.31) */
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
net_ipv6_is_prohibited(const uint8_t *addr, ngx_flag_t allow_local,
    ngx_flag_t allow_private)
{
    if (!allow_local) {
        static const uint8_t loopback6[16] = {
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1
        };

        /* ::1 */
        if (memcmp(addr, loopback6, 16) == 0) {
            return 1;
        }

        /* fe80::/10 */
        if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80) {
            return 1;
        }
    }

    if (!allow_private) {
        /* fc00::/7 — IPv6 Unique Local Addresses */
        if ((addr[0] & 0xfe) == 0xfc) {
            return 1;
        }
    }

    return 0;
}

/*
 * net_addr_check — dispatch a resolved sockaddr to the family-specific
 * prohibited-range test. Returns 1 if the address must be blocked.
 *
 * WHY: this is the single chokepoint every SSRF decision flows through —
 * both the literal-address check and each per-result DNS check call it, so
 * the v4/v6 policy can never diverge between code paths.
 */
int
net_addr_check(const struct sockaddr *sa, ngx_flag_t allow_local,
    ngx_flag_t allow_private)
{
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
        uint32_t addr = ntohl(sin->sin_addr.s_addr);

        return net_ipv4_is_prohibited(addr, allow_local, allow_private);
    }

    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;

#if defined(IN6_IS_ADDR_V4MAPPED)
        /* ::ffff:x.x.x.x — classify using IPv4 rules.
         * SECURITY: a v4-mapped literal (e.g. ::ffff:127.0.0.1) would slip
         * past the v6 tests below, so re-extract the trailing 4 octets
         * (offset 12 in the 16-byte address) and apply the v4 policy. */
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            uint32_t v4;

            v4 = ntohl(*(const uint32_t *) &sin6->sin6_addr.s6_addr[12]);
            return net_ipv4_is_prohibited(v4, allow_local, allow_private);
        }
#endif

        return net_ipv6_is_prohibited(sin6->sin6_addr.s6_addr,
                                      allow_local, allow_private);
    }

    return 0;
}

/*
 * brix_net_target_check_addr — SSRF gate for an already-resolved address.
 *
 * WHAT: returns NGX_OK if sa is permitted under policy, else NGX_ERROR with a
 *       human-readable reason written into err.
 * WHY:  callers that already hold a sockaddr (e.g. a connect target chosen by
 *       lower layers) validate it here without a DNS round-trip.
 */
ngx_int_t
brix_net_target_check_addr(const struct sockaddr *sa,
    const brix_net_target_policy_t *policy,
    char *err, size_t errsz)
{
    if (net_addr_check(sa, policy->allow_local, policy->allow_private)) {
        snprintf(err, errsz,
                 "address is in a prohibited range "
                 "(allow_local=%d allow_private=%d)",
                 (int) policy->allow_local,
                 (int) policy->allow_private);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * brix_net_host_chars_valid — cheap pre-DNS allowlist on the host string.
 *
 * WHAT: returns 1 only if every byte is [A-Za-z0-9.:-] (the chars legal in a
 *       hostname or IPv4/IPv6 literal); 0 otherwise or for empty input.
 * WHY:  rejects shell/whitespace/control bytes and embedded URL trickery
 *       before the host is ever passed to getaddrinfo or a child process.
 */
int
brix_net_host_chars_valid(const char *host, size_t len)
{
    size_t  i;

    if (host == NULL || len == 0) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char) host[i];

        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
            || (ch >= '0' && ch <= '9')
            || ch == '.' || ch == ':' || ch == '-')
        {
            continue;
        }
        return 0;
    }

    return 1;
}
