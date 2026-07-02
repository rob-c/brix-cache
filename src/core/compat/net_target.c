/*
 * net_target.c — shared external transfer target parser and SSRF guard.
 *
 * See net_target.h for the public API.
 *
 * Address classification helpers (ipv4/ipv6 prohibited-range checks) were
 * extracted from src/tpc/connect.c so that WebDAV HTTP-TPC and future S3
 * remote-copy features share the same SSRF policy without reimplementing it.
 */

#include "net_target.h"

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
static int
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
 * xrootd_net_target_check_addr — SSRF gate for an already-resolved address.
 *
 * WHAT: returns NGX_OK if sa is permitted under policy, else NGX_ERROR with a
 *       human-readable reason written into err.
 * WHY:  callers that already hold a sockaddr (e.g. a connect target chosen by
 *       lower layers) validate it here without a DNS round-trip.
 */
ngx_int_t
xrootd_net_target_check_addr(const struct sockaddr *sa,
    const xrootd_net_target_policy_t *policy,
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
 * xrootd_net_target_parse — split "scheme://host[:port][/path]" into fields.
 *
 * WHAT: fills *out with scheme/host/port/path slices for the given URL;
 *       returns NGX_OK or NGX_ERROR with a reason in err.
 * WHY:  HTTP-TPC / remote-copy targets arrive as opaque URL strings and must
 *       be decomposed before the host can be DNS-checked against SSRF policy.
 * HOW:  zero-copy single forward pass — every out->* ngx_str_t points back
 *       into url->data (no allocation), so the parsed target's lifetime is
 *       bound to the caller's url buffer. IPv6 literals in [brackets] are
 *       handled separately from plain host:port because a bare ':' scan would
 *       otherwise mistake the address's colons for a port delimiter.
 */
ngx_int_t
xrootd_net_target_parse(ngx_pool_t *pool,
    const ngx_str_t *url, xrootd_net_target_t *out,
    char *err, size_t errsz)
{
    const u_char *p, *end, *scheme_end, *host_start, *host_end, *colon;

    (void) pool; /* zero-copy: all fields point into url->data */

    if (url == NULL || url->data == NULL || url->len == 0) {
        snprintf(err, errsz, "empty URL");
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(*out));
    out->raw_url = *url;

    p   = url->data;
    end = url->data + url->len;

    /* Find "://" */
    scheme_end = NULL;
    for (const u_char *q = p; q + 2 < end; q++) {
        if (q[0] == ':' && q[1] == '/' && q[2] == '/') {
            scheme_end = q;
            break;
        }
    }

    if (scheme_end == NULL) {
        snprintf(err, errsz, "URL missing '://' separator");
        return NGX_ERROR;
    }

    out->scheme.data = (u_char *) p;
    out->scheme.len  = (size_t) (scheme_end - p);

    if (out->scheme.len == 0) {
        snprintf(err, errsz, "URL has empty scheme");
        return NGX_ERROR;
    }

    /* Skip "://" */
    host_start = scheme_end + 3;
    if (host_start >= end) {
        snprintf(err, errsz, "URL has no host after '://'");
        return NGX_ERROR;
    }

    /* Find end of host[:port] section — first "/" after "://" */
    host_end = host_start;
    while (host_end < end && *host_end != '/') {
        host_end++;
    }

    /* path is from first "/" onward (may be empty) */
    out->path.data = (u_char *) host_end;
    out->path.len  = (size_t) (end - host_end);

    /* Parse host and optional port.
     * IPv6 literals: [addr]:port or [addr].
     * Bracketed form is special-cased first: the address itself contains
     * colons, so the port (if any) is only the ':NNN' that follows the ']'. */
    if (host_start < host_end && *host_start == '[') {
        const u_char *bracket_end = host_start + 1;

        /* scan for the matching ']' bounding the literal */
        while (bracket_end < host_end && *bracket_end != ']') {
            bracket_end++;
        }

        if (bracket_end >= host_end) {
            snprintf(err, errsz, "IPv6 literal missing closing ']'");
            return NGX_ERROR;
        }

        out->host.data = (u_char *) (host_start + 1);
        out->host.len  = (size_t) (bracket_end - (host_start + 1));

        /* Optional :port after ] */
        colon = bracket_end + 1;
        if (colon < host_end && *colon == ':') {
            unsigned long p_val = 0;

            colon++;
            for (const u_char *d = colon; d < host_end; d++) {
                if (*d < '0' || *d > '9') {
                    snprintf(err, errsz, "invalid port in URL");
                    return NGX_ERROR;
                }
                p_val = p_val * 10 + (*d - '0');
                if (p_val > 65535) {
                    snprintf(err, errsz, "port out of range");
                    return NGX_ERROR;
                }
            }

            out->port     = (uint16_t) p_val;
            out->has_port = 1;
        }
    } else {
        /* Plain hostname or IPv4 — find LAST ":" for the port split.
         * Last (not first) is deliberate: a bare unbracketed IPv6 literal has
         * multiple colons and there is no port, so taking the final colon
         * gives a port-parse that then fails the digits-only check below and
         * is rejected, rather than silently truncating the host. */
        colon = NULL;
        for (const u_char *q = host_start; q < host_end; q++) {
            if (*q == ':') {
                colon = q;
            }
        }

        if (colon != NULL) {
            /* Everything after last ":" is the port */
            unsigned long p_val = 0;
            const u_char *d;

            for (d = colon + 1; d < host_end; d++) {
                if (*d < '0' || *d > '9') {
                    snprintf(err, errsz, "invalid port in URL");
                    return NGX_ERROR;
                }
                p_val = p_val * 10 + (*d - '0');
                if (p_val > 65535) {
                    snprintf(err, errsz, "port out of range");
                    return NGX_ERROR;
                }
            }

            out->host.data = (u_char *) host_start;
            out->host.len  = (size_t) (colon - host_start);
            out->port      = (uint16_t) p_val;
            out->has_port  = 1;
        } else {
            out->host.data = (u_char *) host_start;
            out->host.len  = (size_t) (host_end - host_start);
        }
    }

    if (out->host.len == 0) {
        snprintf(err, errsz, "URL has empty host");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * xrootd_net_target_check_dns — resolve target->host and reject if ANY
 * resolved address falls in a prohibited range.
 *
 * WHAT: NGX_OK only when every A/AAAA result passes policy; NGX_ERROR (with
 *       reason in err) on resolution failure or a single prohibited result.
 * WHY:  primary SSRF defence for hostname targets — checking all results,
 *       not just the first, stops a multi-A record from hiding a blocked
 *       address behind a permitted one.
 * HOW:  BLOCKING getaddrinfo — caller MUST invoke this from a thread-pool
 *       worker, never the event loop.  Use check_dns_pin instead when the
 *       validated address must also be handed to the connect step.
 */
ngx_int_t
xrootd_net_target_check_dns(const xrootd_net_target_t *target,
    const xrootd_net_target_policy_t *policy,
    char *err, size_t errsz)
{
    struct addrinfo  hints, *res, *rp;
    char             host_buf[256];
    char             port_str[8];
    uint16_t         port;

    if (target->host.len == 0) {
        snprintf(err, errsz, "target host is empty");
        return NGX_ERROR;
    }

    if (target->host.len >= sizeof(host_buf)) {
        snprintf(err, errsz, "target hostname too long");
        return NGX_ERROR;
    }

    memcpy(host_buf, target->host.data, target->host.len);
    host_buf[target->host.len] = '\0';

    /* Pick a default port when the URL omitted one: scheme "https" (len 5) or
     * a require_https policy implies the TLS port, otherwise the root:// port.
     * The policy value wins if set, else fall back to the IANA defaults. */
    port = target->port;
    if (port == 0) {
        if (policy->require_https || target->scheme.len == 5
            /* "https" */)
        {
            port = policy->default_https_port ? policy->default_https_port : 443;
        } else {
            port = policy->default_root_port ? policy->default_root_port : 1094;
        }
    }

    snprintf(port_str, sizeof(port_str), "%u", (unsigned) port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(host_buf, port_str, &hints, &res) != 0) {
        snprintf(err, errsz, "DNS resolution failed for %s", host_buf);
        return NGX_ERROR;
    }

    /* Reject on the FIRST prohibited result, but only after having scanned up
     * to it — every address must clear policy, so a single bad one fails all. */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (net_addr_check(rp->ai_addr,
                           policy->allow_local,
                           policy->allow_private))
        {
            snprintf(err, errsz,
                     "host %s resolves to a prohibited address "
                     "(allow_local=%d allow_private=%d)",
                     host_buf,
                     (int) policy->allow_local,
                     (int) policy->allow_private);
            freeaddrinfo(res);
            return NGX_ERROR;
        }
    }

    freeaddrinfo(res);
    return NGX_OK;
}

/*
 * xrootd_net_target_check_dns_pin — like check_dns, but also returns the
 * numeric IP of the first permitted address so the caller can connect to that
 * exact address (DNS-rebind defence).
 *
 * WHAT: validates every resolved address against policy and writes the first
 *       permitted one's numeric form into out_ip; NGX_OK / NGX_ERROR.
 * WHY:  validating a hostname then letting a separate component re-resolve it
 *       opens a TOCTOU rebind window (DNS answers differently the 2nd time).
 *       Pinning the validated address closes that window — see loop comment.
 * HOW:  BLOCKING getaddrinfo + getnameinfo(NI_NUMERICHOST); thread-pool only.
 */
ngx_int_t
xrootd_net_target_check_dns_pin(const xrootd_net_target_t *target,
    const xrootd_net_target_policy_t *policy,
    char *out_ip, size_t out_ipsz,
    char *err, size_t errsz)
{
    struct addrinfo  hints, *res, *rp;
    char             host_buf[256];
    char             port_str[8];
    uint16_t         port;

    if (out_ip == NULL || out_ipsz == 0) {
        snprintf(err, errsz, "no pin buffer");
        return NGX_ERROR;
    }
    out_ip[0] = '\0';

    if (target->host.len == 0 || target->host.len >= sizeof(host_buf)) {
        snprintf(err, errsz, "target host is empty or too long");
        return NGX_ERROR;
    }

    memcpy(host_buf, target->host.data, target->host.len);
    host_buf[target->host.len] = '\0';

    port = target->port;
    if (port == 0) {
        if (policy->require_https || target->scheme.len == 5 /* "https" */) {
            port = policy->default_https_port ? policy->default_https_port : 443;
        } else {
            port = policy->default_root_port ? policy->default_root_port : 1094;
        }
    }

    snprintf(port_str, sizeof(port_str), "%u", (unsigned) port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(host_buf, port_str, &hints, &res) != 0) {
        snprintf(err, errsz, "DNS resolution failed for %s", host_buf);
        return NGX_ERROR;
    }

    /*
     * Validate EVERY resolved address (so a multi-A record can't smuggle a
     * prohibited address past the check) and pin the FIRST permitted one.
     * Pinning the exact validated address is what closes the rebind window —
     * a later independent re-resolution by the transfer agent is bypassed.
     */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (net_addr_check(rp->ai_addr, policy->allow_local,
                           policy->allow_private))
        {
            snprintf(err, errsz,
                     "host %s resolves to a prohibited address "
                     "(allow_local=%d allow_private=%d)",
                     host_buf, (int) policy->allow_local,
                     (int) policy->allow_private);
            freeaddrinfo(res);
            return NGX_ERROR;
        }

        if (out_ip[0] == '\0') {
            if (getnameinfo(rp->ai_addr, rp->ai_addrlen, out_ip, out_ipsz,
                            NULL, 0, NI_NUMERICHOST) != 0)
            {
                snprintf(err, errsz, "could not format resolved address for %s",
                         host_buf);
                freeaddrinfo(res);
                return NGX_ERROR;
            }
        }
    }

    freeaddrinfo(res);

    if (out_ip[0] == '\0') {
        snprintf(err, errsz, "no addresses resolved for %s", host_buf);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * xrootd_net_host_chars_valid — cheap pre-DNS allowlist on the host string.
 *
 * WHAT: returns 1 only if every byte is [A-Za-z0-9.:-] (the chars legal in a
 *       hostname or IPv4/IPv6 literal); 0 otherwise or for empty input.
 * WHY:  rejects shell/whitespace/control bytes and embedded URL trickery
 *       before the host is ever passed to getaddrinfo or a child process.
 */
int
xrootd_net_host_chars_valid(const char *host, size_t len)
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
