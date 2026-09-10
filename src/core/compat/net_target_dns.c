/*
 * net_target_dns.c — DNS resolution + SSRF verdict for outbound targets.
 *
 * See net_target.h for the public API.  This translation unit holds the
 * resolving checkers — check_dns / check_dns_pin (blocking, thread-pool
 * only) and check_cached (event loop, never blocks) — and their default-port
 * / resolve / verdict helpers.  Every address comes from the brix DNS driver
 * (phase-116): brix_dns_resolve_sync() for the blocking pair, so the
 * event loop's `brix_resolver` policy, cache and search list govern outbound
 * SSRF checks exactly as they govern every other resolution; and
 * brix_dns_cache_probe() for the cached probe.  Each per-result verdict
 * routes through net_addr_check() (defined in net_target.c, declared in
 * net_target_internal.h) so the v4/v6 policy can never diverge from the
 * literal-address path.
 */

#include "net_target.h"
#include "net_target_internal.h"
#include "cstr.h"
#include "net/dns/dns.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>


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
 * net_target_host — copy the target host into a NUL-terminated buffer.
 *
 * WHAT: NGX_OK with host_buf filled; NGX_ERROR (err set) when the host is
 *       empty or too long.
 * WHY:  the three checkers share the same precondition and message.
 */
static ngx_int_t
net_target_host(const brix_net_target_t *target, char *host_buf,
    size_t host_sz, char *err, size_t errsz)
{
    if (target->host.len == 0) {
        snprintf(err, errsz, "target host is empty");
        return NGX_ERROR;
    }
    if (brix_str_cbuf(host_buf, host_sz, &target->host) == NULL) {
        snprintf(err, errsz, "target hostname too long");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * net_resolve_host — blocking resolution of host_buf on the chosen port.
 *
 * WHAT: fills addrs[] (up to BRIX_DNS_MAX_ADDRS) and returns the count; 0
 *       with "DNS resolution failed for <host>: <reason>" in err.
 * WHY:  both blocking checkers need the same SOCK_STREAM / AF_UNSPEC
 *       resolution and the same failure message — sharing it keeps them
 *       byte-identical.
 * HOW:  BLOCKING brix_dns_resolve_sync() through policy->dns: literal ->
 *       per-worker cache -> the event loop's resolver via the bridge -> libc.
 */
static ngx_uint_t
net_resolve_host(const brix_net_target_policy_t *policy, const char *host_buf,
    uint16_t port, brix_dns_addr_t *addrs, char *err, size_t errsz)
{
    char        reason[BRIX_DNS_ERROR_LEN];
    ngx_uint_t  n;

    n = brix_dns_resolve_sync(policy->dns, host_buf, port, BRIX_AF_AUTO,
                              SOCK_STREAM, addrs, BRIX_DNS_MAX_ADDRS, reason,
                              sizeof(reason));
    if (n == 0) {
        snprintf(err, errsz, "DNS resolution failed for %s: %s", host_buf,
                 reason);
    }
    return n;
}

/*
 * net_addr_is_prohibited_msg — policy-check one resolved address and, on a
 * prohibited result, format the shared rejection message.
 *
 * WHAT: returns 1 (writing the "host <h> resolves to a prohibited address …"
 *       message into err) when sa is blocked under policy; 0 otherwise.
 * WHY:  the per-result reject verdict and its exact wire message are shared by
 *       every checker; one helper keeps the bytes identical.
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
 * net_addrs_verdict — reject on the FIRST prohibited result.
 *
 * WHAT: NGX_OK when every address clears policy; NGX_ERROR (err set) as soon
 *       as one does not.
 * WHY:  every address must clear policy, so a single bad one fails all — a
 *       multi-A record cannot hide a blocked address behind a permitted one.
 */
ngx_int_t
brix_net_target_check_addrs(const brix_dns_addr_t *addrs, ngx_uint_t n,
    const brix_net_target_policy_t *policy, const char *host_buf,
    char *err, size_t errsz)
{
    ngx_uint_t  i;

    for (i = 0; i < n; i++) {
        if (net_addr_is_prohibited_msg((const struct sockaddr *) &addrs[i].ss,
                                       policy, host_buf, err, errsz))
        {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
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
 * HOW:  BLOCKING resolve — caller MUST invoke this from a thread-pool
 *       worker, never the event loop.  Use check_dns_pin instead when the
 *       validated address must also be handed to the connect step, and
 *       check_cached on the event loop.
 */
ngx_int_t
brix_net_target_check_dns(const brix_net_target_t *target,
    const brix_net_target_policy_t *policy,
    char *err, size_t errsz)
{
    brix_dns_addr_t  addrs[BRIX_DNS_MAX_ADDRS];
    char             host_buf[256];
    ngx_uint_t       n;

    if (net_target_host(target, host_buf, sizeof(host_buf), err, errsz)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    n = net_resolve_host(policy, host_buf, net_default_port(target, policy),
                         addrs, err, errsz);
    if (n == 0) {
        return NGX_ERROR;
    }
    return brix_net_target_check_addrs(addrs, n, policy, host_buf, err, errsz);
}

/*
 * brix_net_target_check_cached — check_dns for the event loop.
 *
 * WHAT: NGX_OK / NGX_ERROR as check_dns when an answer is cached (or the
 *       host is an IP literal); NGX_DECLINED when no answer is cached.
 *       Starts nothing.
 * WHY:  loop-side preflights (the native TPC kXR_open gate) must not block
 *       (I-DNS-1); refusing early on a cached prohibited address keeps the
 *       cheap rejection, while an unknown name lets the caller park on its
 *       own async request and deliver the verdict when the answer arrives.
 * HOW:  brix_dns_cache_probe() — literal or cache, NGX_AGAIN otherwise.
 */
ngx_int_t
brix_net_target_check_cached(const brix_net_target_t *target,
    const brix_net_target_policy_t *policy,
    char *err, size_t errsz)
{
    brix_dns_addr_t  addrs[BRIX_DNS_MAX_ADDRS];
    char             host_buf[256];
    char             reason[BRIX_DNS_ERROR_LEN];
    ngx_uint_t       n;
    ngx_int_t        rc;

    if (net_target_host(target, host_buf, sizeof(host_buf), err, errsz)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    rc = brix_dns_cache_probe(policy->dns, host_buf,
                              net_default_port(target, policy), BRIX_AF_AUTO,
                              addrs, BRIX_DNS_MAX_ADDRS, &n, reason,
                              sizeof(reason));
    if (rc == NGX_AGAIN) {
        return NGX_DECLINED;
    }
    if (rc != NGX_OK || n == 0) {
        snprintf(err, errsz, "DNS resolution failed for %s: %s", host_buf,
                 reason);
        return NGX_ERROR;
    }
    return brix_net_target_check_addrs(addrs, n, policy, host_buf, err, errsz);
}

/*
 * net_pin_out_t — the caller-owned buffer that receives the pinned numeric IPs.
 *
 * WHAT: bundles the out_ip pointer with its size so the pin helper takes ONE
 *       struct instead of a (buffer, size) positional pair.
 * WHY:  keeps net_pin_append_addr within the param budget while making the
 *       output-buffer contract explicit; the check_dns_pin public signature
 *       stays frozen — this struct is built locally from its out params.
 * HOW:  a plain view; the buffer is owned by the public caller.
 */
typedef struct {
    char   *buf;
    size_t  size;
} net_pin_out_t;

/*
 * net_pin_append_addr — append this permitted address to the comma-separated
 * pin list.
 *
 * WHAT: writes the numeric form of addr onto the end of pin->buf as
 *       "addr" (first) or ",addr" (subsequent).
 * WHY:  the caller hands the WHOLE validated set to curl via CURLOPT_RESOLVE
 *       ("host:port:addr1,addr2"), so curl can fall back ACROSS address families
 *       (e.g. a loopback host whose "localhost" is ::1-only in /etc/hosts but
 *       whose server listens on 127.0.0.1 — ::1 is refused, curl then tries the
 *       pinned IPv4) WITHOUT ever re-resolving. Pinning every permitted address
 *       is exactly as safe as pinning one: each was policy-checked before this
 *       call, and no independent re-resolution can smuggle a new address in.
 * HOW:  brix_dns_addr_ntop() (numeric, never a lookup) into a scratch buffer,
 *       then append with a leading ',' when the list is non-empty. An address
 *       that would overflow the pin buffer is SKIPPED (not truncated) — the
 *       list keeps >= 1 addr.
 */
static void
net_pin_append_addr(const brix_dns_addr_t *addr, const net_pin_out_t *pin)
{
    char   text[64];   /* INET6_ADDRSTRLEN (46) + slack */
    size_t used = ngx_strlen(pin->buf);
    size_t alen = brix_dns_addr_ntop(addr, text, sizeof(text));

    if (alen == 0 || used + (used ? 1 : 0) + alen + 1 > pin->size) {
        return;            /* buffer full — keep the addresses already pinned */
    }
    if (used) {
        pin->buf[used++] = ',';
    }
    ngx_memcpy(pin->buf + used, text, alen + 1);
}

/*
 * brix_net_target_check_dns_pin — like check_dns, but also returns the numeric
 * IPs of ALL permitted addresses (comma-separated) so the caller can connect to
 * exactly that validated set (DNS-rebind defence) while still falling back
 * across them.
 *
 * WHAT: validates every resolved address against policy and writes the whole
 *       permitted set's numeric forms into out_ip as "addr1,addr2"; NGX_OK /
 *       NGX_ERROR.
 * WHY:  validating a hostname then letting a separate component re-resolve it
 *       opens a TOCTOU rebind window (DNS answers differently the 2nd time).
 *       Pinning the validated set closes that window; pinning ALL of it (not
 *       just the first) also lets curl fall back e.g. ::1 -> 127.0.0.1 for a
 *       dual-stack/loopback host without ever re-resolving — see loop comment.
 * HOW:  BLOCKING resolve through the brix DNS driver; thread-pool only.
 */
ngx_int_t
brix_net_target_check_dns_pin(const brix_net_target_t *target,
    const brix_net_target_policy_t *policy,
    char *out_ip, size_t out_ipsz,
    char *err, size_t errsz)
{
    brix_dns_addr_t  addrs[BRIX_DNS_MAX_ADDRS];
    char             host_buf[256];
    net_pin_out_t    pin = { out_ip, out_ipsz };
    ngx_uint_t       i, n;

    if (out_ip == NULL || out_ipsz == 0) {
        snprintf(err, errsz, "no pin buffer");
        return NGX_ERROR;
    }
    out_ip[0] = '\0';

    if (net_target_host(target, host_buf, sizeof(host_buf), err, errsz)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    n = net_resolve_host(policy, host_buf, net_default_port(target, policy),
                         addrs, err, errsz);
    if (n == 0) {
        return NGX_ERROR;
    }

    /*
     * Validate EVERY resolved address (so a multi-A record can't smuggle a
     * prohibited address past the check) and pin ALL permitted ones (comma-
     * joined). Pinning the exact validated set is what closes the rebind window
     * — a later independent re-resolution by the transfer agent is bypassed —
     * and handing curl the full set lets it fall back across address families.
     */
    if (brix_net_target_check_addrs(addrs, n, policy, host_buf, err, errsz) != NGX_OK) {
        return NGX_ERROR;
    }
    for (i = 0; i < n; i++) {
        net_pin_append_addr(&addrs[i], &pin);
    }

    if (out_ip[0] == '\0') {
        snprintf(err, errsz, "no addresses resolved for %s", host_buf);
        return NGX_ERROR;
    }

    return NGX_OK;
}
