/*
 * net_target_policy.c — transport policy and port selection for net targets.
 *
 * WHAT: enforces the supported outbound URL schemes and derives the single
 *       effective port shared by DNS validation, pinning and connection.
 * WHY:  URL parsing and transfer libraries must make the same transport
 *       decision; treating policy flags as mere port hints creates SSRF gaps.
 * HOW:  exact bounded scheme comparisons, followed by explicit-or-default
 *       port selection with no allocation or I/O.
 */

#include "net_target.h"
#include "../types/tunables.h"

#include <stdio.h>


/*
 * net_scheme_equal — compare a parsed scheme to one supported spelling.
 *
 * WHAT: returns 1 when scheme is an exact, case-insensitive match; 0 otherwise.
 * WHY:  URL schemes are case-insensitive, but prefix matches would let an
 *       attacker smuggle a different transport through a policy decision.
 * HOW:  require equal lengths before applying nginx's ASCII case fold.
 */
static int
net_scheme_equal(const ngx_str_t *scheme, const char *expected, size_t length)
{
    return scheme->len == length
           && ngx_strncasecmp(scheme->data, (u_char *) expected, length) == 0;
}

/*
 * brix_net_target_check_scheme — enforce the outbound transport policy.
 *
 * WHAT: returns NGX_OK for https, for http when TLS is not required, and for
 *       root only when explicitly enabled; returns NGX_ERROR with err for all
 *       other parsed schemes. A scheme-less, caller-built host target remains
 *       valid only when the policy does not require HTTPS.
 * WHY:  require_https and allow_root_scheme are security policy, not default-
 *       port hints. Enforcing them before DNS prevents an unsupported URL from
 *       reaching a resolver or transfer library with different parsing rules.
 * HOW:  exact case-insensitive comparisons over the bounded scheme slice.
 */
ngx_int_t
brix_net_target_check_scheme(const brix_net_target_t *target,
    const brix_net_target_policy_t *policy, char *err, size_t errsz)
{
    if (target->scheme.len == 0) {
        if (!policy->require_https) {
            return NGX_OK;
        }
        snprintf(err, errsz, "target URL scheme is required");
        return NGX_ERROR;
    }

    if (net_scheme_equal(&target->scheme, "https", sizeof("https") - 1)) {
        return NGX_OK;
    }
    if (net_scheme_equal(&target->scheme, "http", sizeof("http") - 1)) {
        if (!policy->require_https) {
            return NGX_OK;
        }
        snprintf(err, errsz, "target URL must use https");
        return NGX_ERROR;
    }
    if (net_scheme_equal(&target->scheme, "root", sizeof("root") - 1)) {
        if (!policy->require_https && policy->allow_root_scheme) {
            return NGX_OK;
        }
        snprintf(err, errsz, "target URL root scheme is not allowed");
        return NGX_ERROR;
    }

    snprintf(err, errsz, "unsupported target URL scheme");
    return NGX_ERROR;
}

/*
 * brix_net_target_effective_port — validate and select a target's dial port.
 *
 * WHAT: returns NGX_OK with one nonzero port for a policy-permitted target;
 *       returns NGX_ERROR with err for a refused scheme or invalid output.
 * WHY:  the security check, DNS lookup and final connection must all use the
 *       same port. Re-deriving defaults at each edge creates pinning gaps.
 * HOW:  validate the scheme, preserve an explicit port, otherwise select the
 *       exact scheme's configured or standard default.
 */
ngx_int_t
brix_net_target_effective_port(const brix_net_target_t *target,
    const brix_net_target_policy_t *policy, uint16_t *port,
    char *err, size_t errsz)
{
    if (port == NULL) {
        snprintf(err, errsz, "target port output is missing");
        return NGX_ERROR;
    }
    if (brix_net_target_check_scheme(target, policy, err, errsz) != NGX_OK) {
        return NGX_ERROR;
    }
    if (target->has_port) {
        if (target->port == 0) {
            snprintf(err, errsz, "target port is invalid");
            return NGX_ERROR;
        }
        *port = target->port;
        return NGX_OK;
    }
    if (net_scheme_equal(&target->scheme, "https", sizeof("https") - 1)) {
        *port = policy->default_https_port
                ? policy->default_https_port : BRIX_PORT_HTTPS_DEFAULT;
        return NGX_OK;
    }
    if (net_scheme_equal(&target->scheme, "http", sizeof("http") - 1)) {
        *port = BRIX_PORT_HTTP_DEFAULT;
        return NGX_OK;
    }

    *port = policy->default_root_port
            ? policy->default_root_port : BRIX_PORT_ROOT_DEFAULT;
    return NGX_OK;
}


/*
 * net_target_same_origin — compare URL origins after default-port expansion.
 *
 * WHAT: returns non-zero only when scheme and host match case-insensitively
 *       and both targets select the same effective port.
 * WHY:  textual explicit/default port differences are the same origin, while
 *       a host, scheme or actual dial-port change must not inherit authority.
 * HOW:  use the shared effective-port decision, then bounded comparisons.
 */
static int
net_target_same_origin(const brix_net_target_t *first,
    const brix_net_target_t *second)
{
    brix_net_target_policy_t  policy;
    uint16_t                  first_port, second_port;
    char                      ignored[64];

    ngx_memzero(&policy, sizeof(policy));
    if (brix_net_target_effective_port(first, &policy, &first_port,
                                       ignored, sizeof(ignored)) != NGX_OK
        || brix_net_target_effective_port(second, &policy, &second_port,
                                          ignored, sizeof(ignored)) != NGX_OK)
    {
        return 0;
    }
    return first->scheme.len == second->scheme.len
           && first->host.len == second->host.len
           && ngx_strncasecmp(first->scheme.data, second->scheme.data,
                              first->scheme.len) == 0
           && ngx_strncasecmp(first->host.data, second->host.data,
                              first->host.len) == 0
           && first_port == second_port;
}


/*
 * brix_net_target_check_redirect — constrain authority across redirects.
 *
 * WHAT: rejects HTTPS-to-non-HTTPS redirects and, by default, every origin
 *       change; returns NGX_OK for a permitted next target.
 * WHY:  the pinned curl loop reuses the caller's method, body and explicit
 *       header list. Following an attacker-selected Location without this
 *       gate can replay bearer tokens or authenticated POST bodies to another
 *       origin even though DNS pinning itself succeeds.
 * HOW:  validate the next scheme, preserve TLS once established, then compare
 *       scheme/host/effective-port unless the caller explicitly declares its
 *       request safe for cross-origin replay.
 */
ngx_int_t
brix_net_target_check_redirect(const brix_net_target_t *initial,
    const brix_net_target_t *next, ngx_flag_t allow_cross_origin,
    char *err, size_t errsz)
{
    brix_net_target_policy_t  policy;

    ngx_memzero(&policy, sizeof(policy));
    if (brix_net_target_check_scheme(next, &policy, err, errsz) != NGX_OK) {
        return NGX_ERROR;
    }
    if (net_scheme_equal(&initial->scheme, "https", sizeof("https") - 1)
        && !net_scheme_equal(&next->scheme, "https", sizeof("https") - 1))
    {
        snprintf(err, errsz, "HTTPS redirect downgrade is not allowed");
        return NGX_ERROR;
    }
    if (!allow_cross_origin && !net_target_same_origin(initial, next)) {
        snprintf(err, errsz, "cross-origin redirect is not allowed");
        return NGX_ERROR;
    }
    return NGX_OK;
}
