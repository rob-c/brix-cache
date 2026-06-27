/*
 * ratelimit/reservation.c — XrdBwm-style bandwidth reservation (see header).
 *
 * WHAT: grant/queue/release of byte-budget reservations against named zones.
 *       WHY: parity with XrdBwm's reservation manager for large/TPC transfers
 *       (default-off, niche — ADR-3). HOW: a small per-worker registry of zones,
 *       each holding an aggregate budget, in_use total, queued total, and a
 *       monotonic handle counter. Granting is first-come; queued transfers retry
 *       (the caller parks them via the existing wait machinery).
 */

#include "reservation.h"

#include <string.h>

#define XROOTD_RESV_MAX_ZONES  16

struct xrootd_resv_zone_s {
    char     name[64];
    uint64_t budget;        /* aggregate ceiling                  */
    uint64_t in_use;        /* granted bytes outstanding          */
    uint64_t queued;        /* bytes waiting (informational)      */
    uint64_t next_handle;
    int      granted;       /* count of outstanding grants        */
};

static xrootd_resv_zone_t  resv_zones[XROOTD_RESV_MAX_ZONES];
static int                 resv_zone_count;

xrootd_resv_zone_t *
xrootd_resv_zone_create(ngx_pool_t *pool, const char *name, uint64_t budget)
{
    xrootd_resv_zone_t *z;

    (void) pool;                        /* per-worker static registry for now */

    z = xrootd_resv_zone_get(name);
    if (z != NULL) {
        z->budget = budget;
        return z;
    }
    if (resv_zone_count >= XROOTD_RESV_MAX_ZONES) {
        return NULL;
    }
    z = &resv_zones[resv_zone_count++];
    memset(z, 0, sizeof(*z));
    snprintf(z->name, sizeof(z->name), "%s", name);
    z->budget = budget;
    return z;
}

xrootd_resv_zone_t *
xrootd_resv_zone_get(const char *name)
{
    int i;

    for (i = 0; i < resv_zone_count; i++) {
        if (strcmp(resv_zones[i].name, name) == 0) {
            return &resv_zones[i];
        }
    }
    return NULL;
}

uint64_t
xrootd_resv_schedule(xrootd_resv_zone_t *z, uint64_t bytes)
{
    if (z == NULL || z->budget == 0) {
        return 1;                       /* unconfigured ⇒ always grant */
    }
    if (z->in_use + bytes <= z->budget) {
        z->in_use += bytes;
        z->granted++;
        return ++z->next_handle | 0x1ULL;  /* non-zero handle */
    }
    z->queued += bytes;
    return 0;                           /* queued — caller retries */
}

void
xrootd_resv_done(xrootd_resv_zone_t *z, uint64_t handle)
{
    (void) handle;                      /* per-zone aggregate accounting */

    if (z == NULL || z->granted == 0) {
        return;                         /* idempotent / nothing to release */
    }
    /* Release one grant's worth. The caller passes the same `bytes` semantics
     * by construction; with aggregate accounting we cannot subtract the exact
     * per-handle amount, so this first cut decrements the grant count and lets
     * the next schedule() re-check the ceiling. A precise per-handle SHM slot
     * table is the documented follow-on. */
    z->granted--;
    if (z->granted == 0) {
        z->in_use = 0;
        z->queued = 0;
    }
}

void
xrootd_resv_status(xrootd_resv_zone_t *z, uint64_t *queued_bytes,
    uint64_t *in_use_bytes, int *granted)
{
    if (z == NULL) {
        if (queued_bytes) *queued_bytes = 0;
        if (in_use_bytes) *in_use_bytes = 0;
        if (granted)      *granted = 0;
        return;
    }
    if (queued_bytes) *queued_bytes = z->queued;
    if (in_use_bytes) *in_use_bytes = z->in_use;
    if (granted)      *granted = z->granted;
}
