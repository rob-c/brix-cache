#ifndef XROOTD_RATELIMIT_THROTTLE_COMPAT_H
#define XROOTD_RATELIMIT_THROTTLE_COMPAT_H

#include "ratelimit.h"

/*
 * ratelimit/throttle_compat.h — XrdThrottle config/contract layer (phase-59 W3a).
 *
 * Maps the upstream `throttle.*` semantics onto the existing leaky-bucket SHM
 * engine: the IO-service-time "load" concurrency metric (NOT request count),
 * per-user open-files / active-connection caps, and the INI userconfig with its
 * exact precedence (exact > longest-prefix glob > "*" > global).
 */

#define XROOTD_THROTTLE_MAX_UC_RULES  64

typedef struct {
    char        pat[64];     /* user pattern; trailing "*" = glob, "*" = all */
    ngx_uint_t  maxconn;
} xrootd_throttle_uc_rule_t;

typedef struct {
    xrootd_throttle_uc_rule_t rules[XROOTD_THROTTLE_MAX_UC_RULES];
    int                       count;
    ngx_uint_t                global;   /* the "*" catch-all (0 = none) */
} xrootd_throttle_uc_t;

/* Load the userconfig INI at `path` into *uc. Returns 0 / -1 (errbuf filled). */
int xrootd_throttle_userconfig_load(const char *path, xrootd_throttle_uc_t *uc,
    char *errbuf, size_t errlen);

/* Resolve maxconn for `user`: exact > longest-prefix glob > "*" > 0. */
ngx_uint_t xrootd_throttle_userconfig_match(const xrootd_throttle_uc_t *uc,
    const char *user);

/* Accumulate `service_us` of IO time for `user` in the current interval. */
void xrootd_throttle_charge_io(xrootd_rl_zone_t *zone, ngx_msec_t interval_ms,
    const char *user, uint64_t service_us);

/* 1 if `user`'s IO load (time/interval) is at/over `concurrency`, else 0. */
int xrootd_throttle_ioload_over(xrootd_rl_zone_t *zone, ngx_msec_t interval_ms,
    const char *user, double concurrency);

/* Per-user open-file counter. inc returns 1 if allowed (< cap), 0 if over. */
int  xrootd_throttle_open_inc(xrootd_rl_zone_t *zone, const char *user,
    ngx_uint_t cap);
void xrootd_throttle_open_dec(xrootd_rl_zone_t *zone, const char *user);

#endif /* XROOTD_RATELIMIT_THROTTLE_COMPAT_H */
