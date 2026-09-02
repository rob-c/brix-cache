/*
 * registry.c — SHM-backed session registry for cross-worker coordination.
 *
 * Stores each session's metadata (sessid, DN, VO list, token_auth) in a shared-
 * memory table so any worker can resolve a session it did not itself create —
 * needed because kXR_bind secondaries and proxied requests may land on a
 * different worker than the primary login.  All slot access is mutex-protected
 * (spin+yield; see shm_slots).  The published-handle table lives in handles.c.
 */

#include "registry.h"
#include "registry_slots_internal.h"   /* slot mechanics: scan/reap/fill/find */
#include "core/compat/shm_slots.h"
#include <ngx_shmtx.h>
#include <string.h>

ngx_shm_zone_t *brix_session_shm_zone;
ngx_shm_zone_t *brix_handle_shm_zone;

static ngx_shmtx_t  brix_session_mutex;

/* Runtime slot count for the session registry (brix_session_slots);
 * defaults to the compile-time capacity. */
static ngx_uint_t   brix_session_registry_nslots =
    BRIX_SESSION_REGISTRY_SLOTS;

/* Per-process pointer to the SHM session table (NULL until the zone is set up). */
static brix_session_table_t *
session_table(void)
{
    /* Single read of zone->data: the checked value IS the returned value. */
    void *table = brix_session_shm_zone ? brix_session_shm_zone->data : NULL;

    if (table == NULL || table == (void *) 1) {
        return NULL;
    }
    return (brix_session_table_t *) table;
}

/* Shared-memory zone init callback: lay the session table out in the zone and
 * create its spin+yield mutex.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t
brix_session_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t               fresh;
    brix_session_table_t  *tbl;

    /*
     * Allocate the table FROM the slab pool (never lay it over shm.addr) so
     * nginx's ngx_unlock_mutexes() — which treats every zone's shm.addr as an
     * ngx_slab_pool_t header on every child death — does not get clobbered and
     * SIGSEGV the master. The helper handles fresh-alloc, reload (data != NULL),
     * and re-attach, creates brix_session_mutex from the table's leading
     * ngx_shmtx_sh_t lock, and publishes the table via shm_zone->data.
     */
    tbl = brix_shm_table_alloc(shm_zone, data,
                                 sizeof(brix_session_table_t)
                                 + (size_t) brix_session_registry_nslots
                                   * sizeof(brix_session_entry_t),
                                 &brix_session_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        tbl->capacity = brix_session_registry_nslots;
    }

    return NGX_OK;
}

/* Config-time setup of the session-registry SHM zone sized for `slots` entries.
 * Returns NGX_OK / NGX_ERROR. */
ngx_int_t
brix_configure_session_registry(ngx_conf_t *cf, ngx_uint_t slots)
{
    ngx_str_t  zone_name = ngx_string("brix_sessions");
    ngx_str_t  handle_zone_name = ngx_string("brix_session_handles");
    size_t     zone_size;

    if (slots == 0) {
        slots = BRIX_SESSION_REGISTRY_SLOTS;
    }
    brix_session_registry_nslots = slots;

    zone_size = brix_shm_zone_size(sizeof(brix_session_table_t)
                + (size_t) slots * sizeof(brix_session_entry_t));
    brix_session_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                     zone_size,
                                                     &ngx_stream_brix_module);
    if (brix_session_shm_zone == NULL) {
        return NGX_ERROR;
    }

    brix_shm_zone_warn_on_resize(cf, brix_session_shm_zone,
                                   "brix_session_slots");

    brix_session_shm_zone->init = brix_session_shm_init_zone;
    brix_session_shm_zone->data = (void *) 1;

    zone_size = brix_shm_zone_size(sizeof(brix_shared_handle_table_t));
    brix_handle_shm_zone = ngx_shared_memory_add(cf, &handle_zone_name,
                                                   zone_size,
                                                   &ngx_stream_brix_module);
    if (brix_handle_shm_zone == NULL) {
        return NGX_ERROR;
    }

    brix_handle_shm_zone->init = brix_handle_shm_init_zone;
    brix_handle_shm_zone->data = (void *) 1;

    return NGX_OK;
}

/* ---- §1.4: which worker owns a session's primary connection ----
 *
 * WHAT: Returns the owner ngx_worker slot recorded at registration, or -1
 *       for an unknown session.
 *
 * WHY: A kXR_bind that lands on a different worker than the session's
 *      primary cannot be offloaded there (the offload conn map is
 *      per-worker); bind_migrate.c uses this to hand the secondary's fd to
 *      the owning worker instead of falling back to inline responses.
 *
 * HOW: Same lock→find→read→unlock shape as the pathid-bitmap operations.
 */
ngx_int_t
brix_session_owner_worker(const u_char sessid[BRIX_SESSION_ID_LEN])
{
    brix_session_table_t *tbl = session_table();
    brix_session_entry_t *e;
    ngx_int_t             owner = -1;

    if (tbl == NULL) {
        return -1;
    }
    ngx_shmtx_lock(&brix_session_mutex);
    e = brix_session_find_locked(tbl, sessid);
    if (e != NULL) {
        owner = e->owner_worker;
    }
    ngx_shmtx_unlock(&brix_session_mutex);
    return owner;
}

/* ---- Set / clear / test a session's bound-pathid bit ----
 *
 * WHAT: brix_session_pathid_bind marks `pathid` bound for `sessid`;
 *       _unbind clears it; _bound returns 1 when it is currently set.
 *       All are no-ops (or 0) for pathid outside 1-253 or an unknown session.
 *
 * WHY: kXR_bind assigns pathids on the SECONDARY connection's worker while
 *      pathid-tagged requests arrive on the primary (any worker), so the
 *      validation truth must live in the shared session registry. Stock
 *      refuses an unbound pathid with kXR_ArgInvalid "invalid path ID"
 *      (verified live against 5.6.9); this bitmap is what makes that answer
 *      possible (parity-audit §1.2) and the groundwork for response
 *      offloading (§1.1).
 *
 * HOW: Lock the registry mutex, find the slot by sessid, set/clear/test bit
 *      pathid in the 32-byte map, unlock. Callers never hold the mutex.
 */
/* Set (`set` != 0) or clear the pathid bit in a session's map under the
 * registry mutex; both bind and unbind are this one guarded slot-mutation. */
static void
brix_session_pathid_set(const u_char sessid[BRIX_SESSION_ID_LEN],
    unsigned pathid, int set)
{
    brix_session_table_t *tbl = session_table();
    brix_session_entry_t *e;

    /* Separate ifs: gcc 11's -fanalyzer loses the non-NULL constraint on an
     * accessor-returned pointer inside a compound || guard and reports an
     * infeasible NULL deref in brix_session_find_locked. */
    if (tbl == NULL) {
        return;
    }
    if (pathid < 1 || pathid > 253) {
        return;
    }
    ngx_shmtx_lock(&brix_session_mutex);
    e = brix_session_find_locked(tbl, sessid);
    if (e != NULL) {
        u_char bit = (u_char) (1u << (pathid % 8));

        if (set) {
            e->pathid_map[pathid / 8] |= bit;
        } else {
            e->pathid_map[pathid / 8] &= (u_char) ~bit;
        }
    }
    ngx_shmtx_unlock(&brix_session_mutex);
}

void
brix_session_pathid_bind(const u_char sessid[BRIX_SESSION_ID_LEN],
    unsigned pathid)
{
    brix_session_pathid_set(sessid, pathid, 1);
}

void
brix_session_pathid_unbind(const u_char sessid[BRIX_SESSION_ID_LEN],
    unsigned pathid)
{
    brix_session_pathid_set(sessid, pathid, 0);
}

int
brix_session_pathid_bound(const u_char sessid[BRIX_SESSION_ID_LEN],
    unsigned pathid)
{
    brix_session_table_t *tbl = session_table();
    brix_session_entry_t *e;
    int                     bound = 0;

    /* Separate ifs — same gcc 11 compound-guard analyzer limitation. */
    if (tbl == NULL) {
        return 0;
    }
    if (pathid < 1 || pathid > 253) {
        return 0;
    }
    ngx_shmtx_lock(&brix_session_mutex);
    e = brix_session_find_locked(tbl, sessid);
    if (e != NULL) {
        bound = (e->pathid_map[pathid / 8] >> (pathid % 8)) & 1u;
    }
    ngx_shmtx_unlock(&brix_session_mutex);
    return bound;
}

/* Store a session's metadata (sessid, DN, VO list, token_auth) in the first free
 * SHM slot at login completion; a no-op if the sessid is already present.
 * W5/P90-27.2: an identity at its per-source soft cap recycles its OWN LRU slot
 * first (self-eviction), so the F4 global reap only ever fires for genuinely
 * diverse load.  Mutex-protected (cross-worker). */
void
brix_session_register(const u_char sessid[BRIX_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth)
{
    brix_session_table_t *tbl;
    brix_session_scan_t     sc;
    ngx_msec_t              now;
    int                     found, reaped = 0;
    char                    src_key[BRIX_SESSION_SRC_KEY_LEN];
    u_char                  victim[BRIX_SESSION_ID_LEN];

    tbl = session_table();
    if (tbl == NULL) {
        return;
    }

    brix_session_src_key(dn, token_auth, src_key);
    now = ngx_current_msec;

    ngx_shmtx_lock(&brix_session_mutex);

    found = brix_session_scan(tbl, sessid, now, src_key, &sc);

    /* Per-source soft cap (W5): over-quota identities recycle their own LRU
     * slot BEFORE consuming a free one or invoking the global reap. */
    if (!found && sc.src_count >= BRIX_SESSION_PER_SOURCE_SOFT_CAP) {
        reaped = brix_session_src_cap_evict(tbl, sc.src_lru_slot,
                                            &sc.free_slot, victim);
    }

    /* Table full and no match: try the Phase 27 F4 reap-on-full defence, which
     * may free the LRU slot (reaped) or reject and count the attempt. */
    if (!found && !reaped && sc.free_slot == tbl->capacity) {
        reaped = brix_session_reap_lru(tbl, now, sc.lru_slot, sc.lru_seen,
                                       &sc.free_slot, victim);
    }

    if (!found && sc.free_slot < tbl->capacity) {
        brix_session_fill_slot(tbl, sc.free_slot, sessid, dn, vo_list,
                               token_auth, src_key, now);
    }

    ngx_shmtx_unlock(&brix_session_mutex);

    /* Unpublish the reaped victim's handles AFTER releasing the session mutex
     * (mirrors brix_session_unregister's lock order: session then handle). */
    if (reaped) {
        brix_session_finish_eviction(victim);
    }
}

/* Look a session up by sessid, copying its DN / VO list / token_auth out (used
 * by kXR_bind secondaries and proxy mode).  Returns 1 on hit, 0 on miss.
 * Mutex-protected. */
int
brix_session_lookup(const u_char sessid[BRIX_SESSION_ID_LEN],
    char *dn_out, size_t dn_size,
    char *vo_out, size_t vo_size,
    ngx_uint_t *token_auth_out)
{
    brix_session_table_t *tbl;
    brix_session_entry_t *e;
    ngx_uint_t              i;
    int                     found = 0;

    tbl = session_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_session_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        if (ngx_memcmp(e->sessid, sessid, BRIX_SESSION_ID_LEN) == 0) {
            ngx_cpystrn((u_char *) dn_out, (u_char *) e->dn, dn_size);
            ngx_cpystrn((u_char *) vo_out, (u_char *) e->vo_list, vo_size);
            *token_auth_out = e->token_auth;
            e->last_seen = ngx_current_msec;  /* F4: activity keeps it off the LRU */
            found = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&brix_session_mutex);
    return found;
}

/* Clear a session's SHM slot at kXR_endsess / disconnect and unpublish all of
 * its handles.  Mutex-protected. */
void
brix_session_unregister(const u_char sessid[BRIX_SESSION_ID_LEN])
{
    brix_session_table_t *tbl;
    brix_session_entry_t *e;
    ngx_uint_t              i;

    tbl = session_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_session_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (e->in_use
            && ngx_memcmp(e->sessid, sessid, BRIX_SESSION_ID_LEN) == 0)
        {
            ngx_memzero(e, sizeof(*e));
            break;
        }
    }

    ngx_shmtx_unlock(&brix_session_mutex);
    brix_session_handle_unpublish_all(sessid);
}
