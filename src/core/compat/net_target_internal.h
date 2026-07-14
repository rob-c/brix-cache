/*
 * net_target_internal.h — cross-file declarations shared between the
 * net_target.c translation units after the phase-size split.
 *
 * WHAT: declares the address-classification chokepoint that is DEFINED in
 *       net_target.c (the SSRF address cluster) but REFERENCED from
 *       net_target_dns.c (the resolve-and-pin cluster).
 * WHY:  the split moved the DNS helpers into their own file; they still route
 *       every per-result verdict through the single v4/v6 policy chokepoint so
 *       the two code paths can never diverge — that requires a non-static,
 *       header-declared symbol.
 */

#ifndef BRIX_NET_TARGET_INTERNAL_H
#define BRIX_NET_TARGET_INTERNAL_H

#include "net_target.h"

/*
 * net_addr_check — dispatch a resolved sockaddr to the family-specific
 * prohibited-range test.  Returns 1 if the address must be blocked.
 *
 * Defined in net_target.c; used by the DNS checkers in net_target_dns.c.
 */
int net_addr_check(const struct sockaddr *sa, ngx_flag_t allow_local,
    ngx_flag_t allow_private);

#endif /* BRIX_NET_TARGET_INTERNAL_H */
