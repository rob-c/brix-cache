#ifndef BRIX_TPC_EGRESS_GUARD_H
#define BRIX_TPC_EGRESS_GUARD_H

/*
 * egress_guard.h — TPC source-host egress allowlist (SSRF policy control).
 *
 * WHAT: an operator-configured allowlist of hostnames a gateway is permitted to
 *   originate a third-party-copy *pull* from. In the TPC-pull model the
 *   destination (this gateway) is the party that dials the named source host, so
 *   an un-guarded gateway is a request-forgery primitive: any client that can
 *   open a TPC destination can steer the server's outbound socket at an
 *   arbitrary host. This guard refuses to originate unless the source host
 *   matches the allowlist.
 *
 * WHY: the pre-existing address-range gate (brix_tpc_check_src_policy →
 *   allow_local/allow_private) only rejects loopback/private *addresses*; it
 *   cannot express "only these known storage endpoints". Naming-based policy is
 *   the complementary control operators actually want, mirroring the reverse-DNS
 *   host allowlist already used by the `host` auth scheme (brix_host_allow).
 *
 * HOW: the pattern match is pure C (no nginx, no allocation) so it unit-tests
 *   standalone; the nginx wrappers iterate the ngx_array_t of configured
 *   patterns and render the kXR_NotAuthorized-grade refusal text. Refusal is
 *   fail-closed and default-deny: when the guard is on, an empty allowlist
 *   permits nothing. The guard is a no-op (returns "allow") when off, so it
 *   never changes behaviour for deployments that do not opt in.
 */

#include <stddef.h>

/*
 * brix_tpc_host_pattern_match — pure host/pattern predicate.
 *
 * Returns 1 if NUL-terminated `host` matches NUL-terminated `pattern`,
 * case-insensitively; 0 otherwise (including any NULL / empty pattern):
 *   - a leading '.' pattern (".cern.ch") is a domain suffix and matches any
 *     host strictly longer than it that ends with it;
 *   - otherwise an exact hostname match.
 * Mirrors brix_host_pattern_match() in src/auth/host/auth.c so the two
 * allowlists share one spelling of the match rule.
 */
int brix_tpc_host_pattern_match(const char *pattern, const char *host);

#ifndef XRDPROTO_NO_NGX
#include <ngx_config.h>
#include <ngx_core.h>

/*
 * brix_tpc_source_allow_match — 1 if `host` matches any pattern in `allow`
 * (an ngx_array_t of ngx_str_t, as filled by ngx_conf_set_str_array_slot),
 * else 0. A NULL or empty array matches nothing (default-deny).
 */
int brix_tpc_source_allow_match(ngx_array_t *allow, const char *host);

/*
 * brix_tpc_source_guard_check — the origination gate decision.
 *
 *   guard_on == 0            → returns 0 (allow; legacy no-op).
 *   host on the allowlist    → returns 0 (allow).
 *   otherwise                → writes a stable refusal message into err[0..errsz)
 *                              and returns -1 (refuse).
 *
 * The refusal text contains the literal "TPC source host not permitted" so the
 * client-side egress self-test (xrddiag tpc-egress) recognises a working guard,
 * and fail2ban/operators can grep a stable phrase.
 */
int brix_tpc_source_guard_check(ngx_flag_t guard_on, ngx_array_t *allow,
    const char *host, char *err, size_t errsz);

#endif /* !XRDPROTO_NO_NGX */

#endif /* BRIX_TPC_EGRESS_GUARD_H */
