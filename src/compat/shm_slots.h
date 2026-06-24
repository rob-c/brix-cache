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

/*
 * Slab-safe SHM table allocation (shm_slots.c).
 *
 * CRITICAL: nginx initialises every shared_memory zone as an ngx_slab_pool_t and
 * its SIGCHLD handler (ngx_unlock_mutexes, run on EVERY child death) walks all
 * zones, treating shm.addr as an ngx_slab_pool_t and force-unlocking sp->mutex.
 * A zone whose init callback lays its own struct directly over shm.addr clobbers
 * that header → the master SIGSEGVs the moment any child exits (e.g. an FRM stage
 * copycmd). These helpers allocate the table FROM the slab pool, leaving the
 * header intact, so any subsystem that forks children is safe.
 *
 * Contract: the table's FIRST member must be an ngx_shmtx_sh_t lock (pass `mtx`
 * to have the process-local handle created from it; pass NULL for lock-less
 * tables such as the metrics counters).
 *
 * xrootd_shm_table_alloc(): handles fresh alloc, reload (data != NULL), and
 *   re-attach (shm.exists). Publishes the table via shm_zone->data AND the slab
 *   pool's ->data (so a reload re-attaches). *fresh is set to 1 only when a brand
 *   new table was allocated (the caller must then initialise its non-lock fields;
 *   on reuse it must NOT, to preserve live state).
 *
 * xrootd_shm_zone_size(): the zone size to request from ngx_shared_memory_add so
 *   ngx_slab_alloc(table_bytes) always fits alongside the slab overhead.
 */
void  *xrootd_shm_table_alloc(ngx_shm_zone_t *shm_zone, void *data,
                              size_t table_bytes, ngx_shmtx_t *mtx,
                              ngx_flag_t *fresh);
size_t xrootd_shm_zone_size(size_t table_bytes);

/*
 * xrootd_shm_zone_warn_on_resize(): emit a config-time WARN when `zn` is being
 * declared at a different size than the same-named zone in the currently running
 * cycle (i.e. an operator changed a slot-count directive and reloaded). nginx
 * cannot resize a live zone, so it allocates a fresh one and the table's contents
 * are dropped for new connections. `directive` names the offending directive in
 * the message. A no-op on first start (no prior cycle). Call right after the
 * matching ngx_shared_memory_add().
 */
void   xrootd_shm_zone_warn_on_resize(ngx_conf_t *cf, ngx_shm_zone_t *zn,
                                      const char *directive);

#endif /* XROOTD_COMPAT_SHM_SLOTS_H */
