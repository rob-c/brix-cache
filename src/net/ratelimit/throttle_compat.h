#ifndef BRIX_RATELIMIT_THROTTLE_COMPAT_H
#define BRIX_RATELIMIT_THROTTLE_COMPAT_H

#include "ratelimit.h"

/*
 * ratelimit/throttle_compat.h — XrdThrottle config/contract layer (phase-59 W3a).
 *
 * Maps the upstream `throttle.*` semantics onto the existing leaky-bucket SHM
 * engine: the IO-service-time "load" concurrency metric (NOT request count),
 * per-user open-files / active-connection caps, and the INI userconfig with its
 * exact precedence (exact > longest-prefix glob > "*" > global).
 */

#define BRIX_THROTTLE_MAX_UC_RULES  64

typedef struct {
    char        pat[64];     /* user pattern; trailing "*" = glob, "*" = all */
    ngx_uint_t  maxconn;
} brix_throttle_uc_rule_t;

typedef struct {
    brix_throttle_uc_rule_t rules[BRIX_THROTTLE_MAX_UC_RULES];
    int                       count;
    ngx_uint_t                global;   /* the "*" catch-all (0 = none) */
} brix_throttle_uc_t;

/* Load the userconfig INI at `path` into *uc. Returns 0 / -1 (errbuf filled). */
int brix_throttle_userconfig_load(const char *path, brix_throttle_uc_t *uc,
    char *errbuf, size_t errlen);

/* Resolve maxconn for `user`: exact > longest-prefix glob > "*" > 0. */
ngx_uint_t brix_throttle_userconfig_match(const brix_throttle_uc_t *uc,
    const char *user);

/* Accumulate `service_us` of IO time for `user` in the current interval. */
void brix_throttle_charge_io(brix_rl_zone_t *zone, ngx_msec_t interval_ms,
    const char *user, uint64_t service_us);

/* 1 if `user`'s IO load (time/interval) is at/over `concurrency`, else 0. */
int brix_throttle_ioload_over(brix_rl_zone_t *zone, ngx_msec_t interval_ms,
    const char *user, double concurrency);

/* Per-user open-file counter. inc returns 1 if allowed (< cap), 0 if over. */
int  brix_throttle_open_inc(brix_rl_zone_t *zone, const char *user,
    ngx_uint_t cap);
void brix_throttle_open_dec(brix_rl_zone_t *zone, const char *user);

#endif /* BRIX_RATELIMIT_THROTTLE_COMPAT_H */
