#ifndef BRIX_RATELIMIT_THROTTLE_COMPAT_H
#define BRIX_RATELIMIT_THROTTLE_COMPAT_H

#include "ratelimit.h"

/*
 * ratelimit/throttle_compat.h — XrdThrottle config/contract layer (phase-59 W3a).
 *
 * Maps the one upstream `throttle.*` semantic BriX enforces onto the existing
 * leaky-bucket SHM engine: the per-user open-files cap, charged on kXR_open and
 * released on close/disconnect.
 *
 * Phase-95 removed the never-wired siblings that used to live here (the
 * IO-service-time "load" metric, the per-user active-connection cap, and the
 * `userconfig` INI matcher).  They were engines without admission points, so
 * they enforced nothing while implying they did; see
 * docs/refactor/phase-95-audit-deadcode-burndown.md.  A future phase that wants
 * them back must land the call site in the same change as the engine.
 */

/* Per-user open-file counter. inc returns 1 if allowed (< cap), 0 if over. */
int  brix_throttle_open_inc(brix_rl_zone_t *zone, const char *user,
    ngx_uint_t cap);
void brix_throttle_open_dec(brix_rl_zone_t *zone, const char *user);

#endif /* BRIX_RATELIMIT_THROTTLE_COMPAT_H */
