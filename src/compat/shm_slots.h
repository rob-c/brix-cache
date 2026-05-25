/*
 * shm_slots.h — Shared-memory slot lifecycle helpers.
 *
 * Lightweight inline utilities for managing SHM-backed slot pools (TPC key registry,
 * cache origin slots, etc.). Pure nginx-core dependency; no protocol-specific logic.
 */

#ifndef XROOTD_COMPAT_SHM_SLOTS_H
#define XROOTD_COMPAT_SHM_SLOTS_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * WHAT: Check whether an SHM slot's expiration timestamp has passed.
 *
 * WHY: Slot pools (TPC key registry, cache origin connections) need to detect expired
 *      entries without scanning the entire pool. This inline helper is called at points
 *      where a slot's expires field is compared against the current time to decide if
 *      it can be reclaimed or reused.
 *
 * HOW: Simple comparison — returns 1 (true) when expires <= now, 0 otherwise.
 */
static ngx_inline ngx_flag_t
xrootd_shm_slot_expired(ngx_msec_t now, ngx_msec_t expires)
{
    return expires <= now;
}

/*
 * WHAT: Remember a candidate free slot in a pointer when no slot is known yet.
 *
 * WHY: SHM slot pools often track one 'free_slot' index across multiple workers or
 *      iterations. When the tracked value is still at its sentinel ('none'), this helper
 *      records the first available candidate without overwriting later discoveries.
 *
 * HOW: If *free_slot == none, set *free_slot = candidate. Otherwise leave it unchanged.
 *      This prevents a late-arriving worker from clobbering an earlier discovery.
 */
static ngx_inline void
xrootd_shm_remember_free_slot(ngx_uint_t *free_slot, ngx_uint_t none,
    ngx_uint_t candidate)
{
    if (*free_slot == none) {
        *free_slot = candidate;
    }
}

#endif /* XROOTD_COMPAT_SHM_SLOTS_H */
