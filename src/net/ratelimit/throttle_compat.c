/*
 * ratelimit/throttle_compat.c — XrdThrottle contract layer (see header).
 *
 * WHAT: the per-user open-file counters that reproduce upstream's
 *       `throttle.max_open_files` on top of the existing SHM leaky-bucket
 *       engine. WHY: gives that part of the XrdThrottle admin contract natively.
 *       HOW: per-user SHM nodes reuse brix_rl_lookup/create_locked under the
 *       spin+yield zone mutex (INVARIANT 10).
 */

#include "throttle_compat.h"

#include <string.h>

/* SHM-backed open-file counters */
static brix_rl_node_t *
throttle_node_locked(brix_rl_zone_t *zone, const char *user)
{
    uint32_t          h = brix_rl_hash(user, strlen(user));
    brix_rl_node_t *n = brix_rl_lookup_locked(zone, h, user, strlen(user));

    if (n == NULL) {
        n = brix_rl_create_locked(zone, h, user, strlen(user));
    }
    return n;
}

int
brix_throttle_open_inc(brix_rl_zone_t *zone, const char *user,
    ngx_uint_t cap)
{
    brix_rl_node_t *n;
    int               ok = 1;

    if (zone == NULL || zone->sh == NULL || cap == 0) {
        return 1;                       /* unlimited */
    }
    ngx_shmtx_lock(&zone->shpool->mutex);
    n = throttle_node_locked(zone, user);
    if (n != NULL) {
        if (n->open_files < cap) {
            n->open_files++;
            ok = 1;
        } else {
            ok = 0;                     /* over the per-user cap */
        }
    }                                   /* n==NULL (slab OOM) ⇒ fail-open */
    ngx_shmtx_unlock(&zone->shpool->mutex);
    return ok;
}

void
brix_throttle_open_dec(brix_rl_zone_t *zone, const char *user)
{
    brix_rl_node_t *n;

    if (zone == NULL || zone->sh == NULL) {
        return;
    }
    ngx_shmtx_lock(&zone->shpool->mutex);
    n = brix_rl_lookup_locked(zone, brix_rl_hash(user, strlen(user)),
                                user, strlen(user));
    if (n != NULL && n->open_files > 0) {
        n->open_files--;
    }
    ngx_shmtx_unlock(&zone->shpool->mutex);
}
