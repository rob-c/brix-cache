/*
 * net_target.c — shared external transfer target parser and SSRF guard.
 *
 * See net_target.h for the public API.
 *
 * Address classification helpers (ipv4/ipv6 prohibited-range checks) were
 * extracted from src/tpc/outbound/connect.c so that WebDAV HTTP-TPC and future S3
 * remote-copy features share the same SSRF policy without reimplementing it.
 */

#include "net_target.h"
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
 * net_url_span_t — the [start, end) authority substring of a URL and the
 * error sink shared across the parse sub-steps.
 *
 * WHAT: names the two cursors ("host_start" = first byte after "://",
 *       "host_end" = the first '/' or end-of-URL) plus the caller's err
 *       buffer, so a helper takes ONE struct instead of four positional args.
 * WHY:  the parse grammar walks a single authority section (host[:port]); the
 *       three host-form handlers all need the same span + err sink, and passing
 *       them as one struct keeps the sub-parsers under the param budget and
 *       makes the data flow explicit (no reaching back into the orchestrator).
 * HOW:  purely a view — no ownership; the cursors point into the caller's URL
 *       buffer exactly as the zero-copy parser requires.
 */
typedef struct {
    const u_char *host_start;
    const u_char *host_end;
    char         *err;
    size_t        errsz;
} net_url_span_t;

/*
 * net_parse_scheme — locate "://" and record the scheme slice.
 *
 * WHAT: on success sets out->scheme and returns the first byte after "://"
 *       (the host_start cursor); on a missing/empty scheme writes err and
 *       returns NULL.
 * WHY:  isolates the scheme grammar (the "://" scan + emptiness checks) from
 *       the authority grammar so each is independently readable.
 * HOW:  linear forward scan for the ':' '/' '/' triple; slices are zero-copy
 *       into url->data.
 */
static const u_char *
net_parse_scheme(const ngx_str_t *url, brix_net_target_t *out,
    char *err, size_t errsz)
{
    const u_char *p   = url->data;
    const u_char *end = url->data + url->len;
    const u_char *scheme_end = NULL;
    const u_char *host_start;

    /* Find "://" */
    for (const u_char *q = p; q + 2 < end; q++) {
        if (q[0] == ':' && q[1] == '/' && q[2] == '/') {
            scheme_end = q;
            break;
        }
    }

    if (scheme_end == NULL) {
        snprintf(err, errsz, "URL missing '://' separator");
        return NULL;
    }

    out->scheme.data = (u_char *) p;
    out->scheme.len  = (size_t) (scheme_end - p);

    if (out->scheme.len == 0) {
        snprintf(err, errsz, "URL has empty scheme");
        return NULL;
    }

    /* Skip "://" */
    host_start = scheme_end + 3;
    if (host_start >= end) {
        snprintf(err, errsz, "URL has no host after '://'");
        return NULL;
    }

    return host_start;
}

/*
 * net_parse_port_digits — parse a digits-only port field in [begin, end).
 *
 * WHAT: on success writes the value to *out_port and returns NGX_OK; on any
 *       non-digit byte or a value above 65535 writes err and returns NGX_ERROR.
 * WHY:  the bracketed-IPv6 and plain-host branches both parse a port with
 *       identical rules; one shared scanner keeps the grammar (and the exact
 *       "invalid port" / "port out of range" messages) in a single place.
 * HOW:  pure decimal accumulation with an in-loop range clamp; no I/O.
 */
static ngx_int_t
net_parse_port_digits(const u_char *begin, const u_char *end,
    uint16_t *out_port, char *err, size_t errsz)
{
    unsigned long p_val = 0;

    for (const u_char *d = begin; d < end; d++) {
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

    *out_port = (uint16_t) p_val;
    return NGX_OK;
}

/*
 * net_parse_bracketed_host — parse an IPv6 literal authority "[addr][:port]".
 *
 * WHAT: fills out->host with the address inside the brackets and, when a
 *       ":port" follows the ']', out->port/has_port; returns NGX_OK or writes
 *       err and returns NGX_ERROR.
 * WHY:  the bracketed form must be handled apart from the plain scan because
 *       the address itself contains colons — a bare ':' split would mistake
 *       them for a port delimiter.
 * HOW:  scan to the matching ']' bounding the literal, then treat only the
 *       ':NNN' that follows it (if any) as the port.
 */
static ngx_int_t
net_parse_bracketed_host(const net_url_span_t *span, brix_net_target_t *out)
{
    const u_char *bracket_end = span->host_start + 1;
    const u_char *colon;

    /* scan for the matching ']' bounding the literal */
    while (bracket_end < span->host_end && *bracket_end != ']') {
        bracket_end++;
    }

    if (bracket_end >= span->host_end) {
        snprintf(span->err, span->errsz, "IPv6 literal missing closing ']'");
        return NGX_ERROR;
    }

    out->host.data = (u_char *) (span->host_start + 1);
    out->host.len  = (size_t) (bracket_end - (span->host_start + 1));

    /* Optional :port after ] */
    colon = bracket_end + 1;
    if (colon < span->host_end && *colon == ':') {
        if (net_parse_port_digits(colon + 1, span->host_end, &out->port,
                                  span->err, span->errsz) != NGX_OK)
        {
            return NGX_ERROR;
        }
        out->has_port = 1;
    }

    return NGX_OK;
}

/*
 * net_parse_plain_host — parse a hostname / IPv4 authority "host[:port]".
 *
 * WHAT: fills out->host and, when a port is present, out->port/has_port;
 *       returns NGX_OK or writes err and returns NGX_ERROR.
 * WHY:  splits the port on the LAST ':' (not the first) deliberately: a bare
 *       unbracketed IPv6 literal has multiple colons and no port, so taking the
 *       final colon yields a port-parse that then fails the digits-only check
 *       and is rejected — rather than silently truncating the host.
 * HOW:  find the last ':' in the span; everything after it is the port field.
 */
static ngx_int_t
net_parse_plain_host(const net_url_span_t *span, brix_net_target_t *out)
{
    const u_char *colon = NULL;

    for (const u_char *q = span->host_start; q < span->host_end; q++) {
        if (*q == ':') {
            colon = q;
        }
    }

    if (colon == NULL) {
        out->host.data = (u_char *) span->host_start;
        out->host.len  = (size_t) (span->host_end - span->host_start);
        return NGX_OK;
    }

    /* Everything after last ":" is the port */
    if (net_parse_port_digits(colon + 1, span->host_end, &out->port,
                              span->err, span->errsz) != NGX_OK)
    {
        return NGX_ERROR;
    }

    out->host.data = (u_char *) span->host_start;
    out->host.len  = (size_t) (colon - span->host_start);
    out->has_port  = 1;

    return NGX_OK;
}

/*
 * net_parse_authority — parse the host[:port] authority after "://".
 *
 * WHAT: sets out->host/port/has_port from span, dispatching to the bracketed
 *       or plain handler; returns NGX_OK or writes err and returns NGX_ERROR.
 * WHY:  a single dispatch point keeps the orchestrator flat and makes the
 *       bracketed-vs-plain choice the only branch either handler has to know.
 * HOW:  a leading '[' selects the IPv6-literal grammar; anything else is a
 *       plain hostname / IPv4 authority.
 */
static ngx_int_t
net_parse_authority(const net_url_span_t *span, brix_net_target_t *out)
{
    if (span->host_start < span->host_end && *span->host_start == '[') {
        return net_parse_bracketed_host(span, out);
    }

    return net_parse_plain_host(span, out);
}

/*
 * brix_net_target_parse — split "scheme://host[:port][/path]" into fields.
 *
 * WHAT: fills *out with scheme/host/port/path slices for the given URL;
 *       returns NGX_OK or NGX_ERROR with a reason in err.
 * WHY:  HTTP-TPC / remote-copy targets arrive as opaque URL strings and must
 *       be decomposed before the host can be DNS-checked against SSRF policy.
 * HOW:  zero-copy single forward pass — scheme / authority / path grammars are
 *       each parsed by a dedicated helper, and every out->* ngx_str_t points
 *       back into url->data (no allocation), so the parsed target's lifetime is
 *       bound to the caller's url buffer.
 */
ngx_int_t
brix_net_target_parse(ngx_pool_t *pool,
    const ngx_str_t *url, brix_net_target_t *out,
    char *err, size_t errsz)
{
    const u_char   *end, *host_start, *host_end;
    net_url_span_t  span;

    (void) pool; /* zero-copy: all fields point into url->data */

    if (url == NULL || url->data == NULL || url->len == 0) {
        snprintf(err, errsz, "empty URL");
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(*out));
    out->raw_url = *url;

    end = url->data + url->len;

    host_start = net_parse_scheme(url, out, err, errsz);
    if (host_start == NULL) {
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

    span.host_start = host_start;
    span.host_end   = host_end;
    span.err        = err;
    span.errsz      = errsz;

    if (net_parse_authority(&span, out) != NGX_OK) {
        return NGX_ERROR;
    }

    if (out->host.len == 0) {
        snprintf(err, errsz, "URL has empty host");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * net_default_port — resolve the port to use when the URL omitted one.
 *
 * WHAT: returns target->port when explicit, else the policy/scheme default.
 * WHY:  identical fallback rules feed both DNS entry points; one helper keeps
 *       the "https implies TLS port, otherwise root:// port; policy value wins,
 *       else IANA default" decision in a single place.
 * HOW:  pure — scheme "https" (len 5) or a require_https policy selects the
 *       TLS port; the policy value wins over the IANA fallback (443 / 1094).
 */
static uint16_t
net_default_port(const brix_net_target_t *target,
    const brix_net_target_policy_t *policy)
{
    if (target->port != 0) {
        return target->port;
    }

    if (policy->require_https || target->scheme.len == 5 /* "https" */) {
        return policy->default_https_port ? policy->default_https_port : 443;
    }

    return policy->default_root_port ? policy->default_root_port : 1094;
}

/*
 * net_resolve_host — blocking getaddrinfo for host_buf on the chosen port.
 *
 * WHAT: on success stores the addrinfo list in *out_res and returns NGX_OK;
 *       on failure writes "DNS resolution failed for <host>" and returns
 *       NGX_ERROR.
 * WHY:  both DNS checkers need the same SOCK_STREAM / AF_UNSPEC resolution and
 *       the same failure message — sharing it keeps them byte-identical.
 * HOW:  BLOCKING getaddrinfo; caller frees the list with freeaddrinfo().
 */
static ngx_int_t
net_resolve_host(const char *host_buf, uint16_t port,
    struct addrinfo **out_res, char *err, size_t errsz)
{
    struct addrinfo  hints;
    char             port_str[8];

    snprintf(port_str, sizeof(port_str), "%u", (unsigned) port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(host_buf, port_str, &hints, out_res) != 0) {
        snprintf(err, errsz, "DNS resolution failed for %s", host_buf);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * net_addr_is_prohibited_msg — policy-check one resolved address and, on a
 * prohibited result, format the shared rejection message.
 *
 * WHAT: returns 1 (writing the "host <h> resolves to a prohibited address …"
 *       message into err) when sa is blocked under policy; 0 otherwise.
 * WHY:  the per-result reject verdict and its exact wire message are shared by
 *       check_dns and check_dns_pin; one helper keeps the bytes identical.
 * HOW:  delegates the range test to net_addr_check(); no I/O beyond err.
 */
static int
net_addr_is_prohibited_msg(const struct sockaddr *sa,
    const brix_net_target_policy_t *policy, const char *host_buf,
    char *err, size_t errsz)
{
    if (!net_addr_check(sa, policy->allow_local, policy->allow_private)) {
        return 0;
    }

    snprintf(err, errsz,
             "host %s resolves to a prohibited address "
             "(allow_local=%d allow_private=%d)",
             host_buf,
             (int) policy->allow_local,
             (int) policy->allow_private);
    return 1;
}

/*
 * brix_net_target_check_dns — resolve target->host and reject if ANY
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
brix_net_target_check_dns(const brix_net_target_t *target,
    const brix_net_target_policy_t *policy,
    char *err, size_t errsz)
{
    struct addrinfo  *res, *rp;
    char              host_buf[256];

    if (target->host.len == 0) {
        snprintf(err, errsz, "target host is empty");
        return NGX_ERROR;
    }

    if (brix_str_cbuf(host_buf, sizeof(host_buf), &target->host) == NULL) {
        snprintf(err, errsz, "target hostname too long");
        return NGX_ERROR;
    }

    if (net_resolve_host(host_buf, net_default_port(target, policy),
                         &res, err, errsz) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Reject on the FIRST prohibited result, but only after having scanned up
     * to it — every address must clear policy, so a single bad one fails all. */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (net_addr_is_prohibited_msg(rp->ai_addr, policy, host_buf,
                                       err, errsz))
        {
            freeaddrinfo(res);
            return NGX_ERROR;
        }
    }

    freeaddrinfo(res);
    return NGX_OK;
}

/*
 * net_pin_out_t — the caller-owned buffer that receives the pinned numeric IP.
 *
 * WHAT: bundles the out_ip pointer with its size so the pin helper takes ONE
 *       struct instead of a (buffer, size) positional pair.
 * WHY:  keeps net_pin_first_addr within the param budget while making the
 *       output-buffer contract explicit; the check_dns_pin public signature
 *       stays frozen — this struct is built locally from its out params.
 * HOW:  a plain view; the buffer is owned by the public caller.
 */
typedef struct {
    char   *buf;
    size_t  size;
} net_pin_out_t;

/*
 * net_pin_first_addr — format the first permitted address into pin->buf once.
 *
 * WHAT: when pin->buf is still empty, writes the numeric form of rp into it;
 *       returns NGX_OK, or NGX_ERROR (with err set) if getnameinfo fails.
 * WHY:  keeps the "pin only the first permitted address" bookkeeping out of
 *       the scan loop so the loop reads as check-then-pin.
 * HOW:  getnameinfo(NI_NUMERICHOST); no-op once pin->buf is already populated.
 */
static ngx_int_t
net_pin_first_addr(const struct addrinfo *rp, const char *host_buf,
    const net_pin_out_t *pin, char *err, size_t errsz)
{
    if (pin->buf[0] != '\0') {
        return NGX_OK;
    }

    if (getnameinfo(rp->ai_addr, rp->ai_addrlen, pin->buf, pin->size,
                    NULL, 0, NI_NUMERICHOST) != 0)
    {
        snprintf(err, errsz, "could not format resolved address for %s",
                 host_buf);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * brix_net_target_check_dns_pin — like check_dns, but also returns the
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
brix_net_target_check_dns_pin(const brix_net_target_t *target,
    const brix_net_target_policy_t *policy,
    char *out_ip, size_t out_ipsz,
    char *err, size_t errsz)
{
    struct addrinfo  *res, *rp;
    char              host_buf[256];
    net_pin_out_t     pin = { out_ip, out_ipsz };

    if (out_ip == NULL || out_ipsz == 0) {
        snprintf(err, errsz, "no pin buffer");
        return NGX_ERROR;
    }
    out_ip[0] = '\0';

    if (target->host.len == 0
        || brix_str_cbuf(host_buf, sizeof(host_buf), &target->host) == NULL)
    {
        snprintf(err, errsz, "target host is empty or too long");
        return NGX_ERROR;
    }

    if (net_resolve_host(host_buf, net_default_port(target, policy),
                         &res, err, errsz) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * Validate EVERY resolved address (so a multi-A record can't smuggle a
     * prohibited address past the check) and pin the FIRST permitted one.
     * Pinning the exact validated address is what closes the rebind window —
     * a later independent re-resolution by the transfer agent is bypassed.
     */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (net_addr_is_prohibited_msg(rp->ai_addr, policy, host_buf,
                                       err, errsz))
        {
            freeaddrinfo(res);
            return NGX_ERROR;
        }

        if (net_pin_first_addr(rp, host_buf, &pin, err, errsz) != NGX_OK) {
            freeaddrinfo(res);
            return NGX_ERROR;
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
