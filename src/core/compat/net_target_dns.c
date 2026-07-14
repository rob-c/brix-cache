/*
 * net_target_dns.c — DNS resolution + SSRF verdict for outbound targets.
 *
 * See net_target.h for the public API.  Split verbatim from net_target.c:
 * this translation unit holds the blocking getaddrinfo checkers
 * (check_dns / check_dns_pin) and their default-port / resolve / verdict
 * helpers.  Each per-result verdict routes through net_addr_check() (defined
 * in net_target.c, declared in net_target_internal.h) so the v4/v6 policy can
 * never diverge from the literal-address path.
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
