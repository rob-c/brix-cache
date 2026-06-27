#ifndef XROOTD_RATELIMIT_RESERVATION_H
#define XROOTD_RATELIMIT_RESERVATION_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * ratelimit/reservation.h — XrdBwm-style bandwidth reservation (phase-59 W3b).
 *
 * A transfer reserves a byte budget against a named zone; if the zone's
 * aggregate budget is free the reservation is granted (returns a handle),
 * otherwise it is queued (returns 0). done() releases a granted handle and
 * wakes the next queued one. Default-off, niche (ADR-3): the modern fairness
 * story is the throttle/ratelimit engine. This first cut tracks the budget
 * per-worker; a cross-worker SHM upgrade is a follow-on.
 */

typedef struct xrootd_resv_zone_s xrootd_resv_zone_t;

/* Create/lookup a reservation zone with an aggregate bytes/sec budget. */
xrootd_resv_zone_t *xrootd_resv_zone_create(ngx_pool_t *pool, const char *name,
    uint64_t budget);
xrootd_resv_zone_t *xrootd_resv_zone_get(const char *name);

/* Reserve `bytes`. Returns a non-zero handle if granted, 0 if queued/over. */
uint64_t xrootd_resv_schedule(xrootd_resv_zone_t *z, uint64_t bytes);

/* Release a previously granted handle (idempotent). */
void xrootd_resv_done(xrootd_resv_zone_t *z, uint64_t handle);

/* Snapshot: queued / granted-in-use bytes / granted count. */
void xrootd_resv_status(xrootd_resv_zone_t *z, uint64_t *queued_bytes,
    uint64_t *in_use_bytes, int *granted);

#endif /* XROOTD_RATELIMIT_RESERVATION_H */
