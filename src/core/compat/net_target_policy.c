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
