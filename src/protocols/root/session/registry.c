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
    if (brix_session_shm_zone == NULL
        || brix_session_shm_zone->data == NULL
        || brix_session_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_session_table_t *) brix_session_shm_zone->data;
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

/* ---- Scan the session table for a sessid, tracking free and LRU slots ----
 *
 * WHAT: Walks every occupied slot looking for `sessid`.  On a hit it refreshes
 * that slot's last_seen to `now` and returns 1.  On a miss it returns 0 and, via
 * the out-params, reports the first free slot index (or tbl->capacity if none)
 * and the least-recently-seen occupied slot index + its last_seen (used for
 * reap-on-full); lru_slot is tbl->capacity when the table holds no occupied slot.
 *
 * WHY: Isolates the single linear pass over the SHM table so the caller stays a
 * flat sequence of decisions.  Must run with brix_session_mutex held — it reads
 * and (on a hit) writes shared slot state.
 *
 * HOW:
 *   1. Seed all three out-params to their empty-table defaults.
 *   2. For each slot: record the first free one and skip it.
 *   3. On a sessid match, stamp last_seen and return 1.
 *   4. Otherwise fold the occupied slot into the running LRU minimum.
 *   5. Return 0 if no slot matched.
 */
static int
brix_session_scan(brix_session_table_t *tbl,
    const u_char sessid[BRIX_SESSION_ID_LEN], ngx_msec_t now,
    ngx_uint_t *free_slot_out, ngx_uint_t *lru_slot_out,
    ngx_msec_t *lru_seen_out)
{
    brix_session_entry_t *e;
    ngx_uint_t              i;

    *free_slot_out = tbl->capacity;
    *lru_slot_out  = tbl->capacity;
    *lru_seen_out  = 0;

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            if (*free_slot_out == tbl->capacity) {
                *free_slot_out = i;
            }
            continue;
        }
        if (ngx_memcmp(e->sessid, sessid, BRIX_SESSION_ID_LEN) == 0) {
            e->last_seen = now;        /* refresh activity on re-register */
            return 1;
        }
        /* Track the global-LRU occupied slot for reap-on-full (F4). */
        if (*lru_slot_out == tbl->capacity || e->last_seen < *lru_seen_out) {
            *lru_slot_out = i;
            *lru_seen_out = e->last_seen;
        }
    }

    return 0;
}

/* ---- Reap the LRU slot when the table is full, else count the rejection ----
 *
 * WHAT: Phase 27 F4 slot-exhaustion defence, invoked only when no free slot and
 * no matching session were found.  If the LRU slot is older than the minimum reap
 * age it copies that slot's sessid into `victim`, clears the slot, publishes its
 * index via `free_slot_out`, and returns 1.  Otherwise it increments the
 * registry-full metric and returns 0 (leaving `victim`/`free_slot_out` untouched).
 *
 * WHY: A slot-exhaustion attacker must not be able to permanently deny new
 * logins; reaping the least-recently-seen aged session bounds that.  Must run
 * with brix_session_mutex held — it mutates shared slot state.
 *
 * HOW:
 *   1. If an aged LRU slot exists, snapshot its sessid, zero the slot, hand its
 *      index back as the free slot, and return 1.
 *   2. Otherwise bump session_registry_full_total (if metrics are up) and
 *      return 0.
 */
static int
brix_session_reap_lru(brix_session_table_t *tbl, ngx_msec_t now,
    ngx_uint_t lru_slot, ngx_msec_t lru_seen,
    ngx_uint_t *free_slot_out, u_char victim[BRIX_SESSION_ID_LEN])
{
    ngx_brix_metrics_t *m;

    if (lru_slot < tbl->capacity
        && (now - lru_seen) >= BRIX_SESSION_REAP_MIN_AGE_MS)
    {
        ngx_memcpy(victim, tbl->slots[lru_slot].sessid, BRIX_SESSION_ID_LEN);
        ngx_memzero(&tbl->slots[lru_slot], sizeof(tbl->slots[lru_slot]));
        *free_slot_out = lru_slot;
        return 1;
    }

    m = brix_metrics_shared();
    if (m != NULL) {
        (void) ngx_atomic_fetch_add(&m->session_registry_full_total, 1);
    }
    return 0;
}

/* ---- Populate a free session slot with a login's metadata ----
 *
 * WHAT: Writes sessid, DN, VO list and token_auth into slot `slot` and marks it
 * in_use with last_seen = now.  No return value.
 *
 * WHY: Keeps the field-by-field copy (with NULL-string coalescing and bounded
 * ngx_cpystrn) in one named place off the register orchestrator.  Must run with
 * brix_session_mutex held — it writes shared slot state.
 *
 * HOW:
 *   1. Copy the fixed-length sessid.
 *   2. Bounded-copy DN and VO list, substituting "" for NULL inputs.
 *   3. Store token_auth and last_seen, then flag the slot in_use.
 */
static void
brix_session_fill_slot(brix_session_table_t *tbl, ngx_uint_t slot,
    const u_char sessid[BRIX_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth,
    ngx_msec_t now)
{
    brix_session_entry_t *e = &tbl->slots[slot];

    ngx_memcpy(e->sessid, sessid, BRIX_SESSION_ID_LEN);
    ngx_cpystrn((u_char *) e->dn, (u_char *) (dn ? dn : ""), sizeof(e->dn));
    ngx_cpystrn((u_char *) e->vo_list, (u_char *) (vo_list ? vo_list : ""),
                sizeof(e->vo_list));
    e->token_auth = token_auth;
    e->last_seen  = now;
    e->in_use     = 1;
}

/* ---- Finish an eviction after the session mutex is released ----
 *
 * WHAT: Increments the eviction metric and unpublishes every handle owned by the
 * reaped `victim` session.  No return value.
 *
 * WHY: Handle unpublish MUST happen AFTER releasing brix_session_mutex to mirror
 * brix_session_unregister's lock order (session then handle) and avoid a lock
 * inversion.  Keeping it in its own helper makes that ordering contract explicit.
 *
 * HOW:
 *   1. Bump session_evict_total (if metrics are up).
 *   2. Unpublish all of the victim's handles via the handle table.
 */
static void
brix_session_finish_eviction(const u_char victim[BRIX_SESSION_ID_LEN])
{
    ngx_brix_metrics_t *m = brix_metrics_shared();

    if (m != NULL) {
        (void) ngx_atomic_fetch_add(&m->session_evict_total, 1);
    }
    brix_session_handle_unpublish_all(victim);
}

/* Store a session's metadata (sessid, DN, VO list, token_auth) in the first free
 * SHM slot at login completion; a no-op if the sessid is already present.
 * Mutex-protected (cross-worker). */
void
brix_session_register(const u_char sessid[BRIX_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth)
{
    brix_session_table_t *tbl;
    ngx_uint_t              free_slot, lru_slot;
    ngx_msec_t              now, lru_seen;
    int                     found, reaped = 0;
    u_char                  victim[BRIX_SESSION_ID_LEN];

    tbl = session_table();
    if (tbl == NULL) {
        return;
    }

    now = ngx_current_msec;

    ngx_shmtx_lock(&brix_session_mutex);

    found = brix_session_scan(tbl, sessid, now,
                              &free_slot, &lru_slot, &lru_seen);

    /* Table full and no match: try the Phase 27 F4 reap-on-full defence, which
     * may free the LRU slot (reaped) or reject and count the attempt. */
    if (!found && free_slot == tbl->capacity) {
        reaped = brix_session_reap_lru(tbl, now, lru_slot, lru_seen,
                                       &free_slot, victim);
    }

    if (!found && free_slot < tbl->capacity) {
        brix_session_fill_slot(tbl, free_slot, sessid, dn, vo_list,
                               token_auth, now);
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
