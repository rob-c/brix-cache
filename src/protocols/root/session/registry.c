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

ngx_shm_zone_t *xrootd_session_shm_zone;
ngx_shm_zone_t *xrootd_handle_shm_zone;

static ngx_shmtx_t  xrootd_session_mutex;

/* Runtime slot count for the session registry (xrootd_session_slots);
 * defaults to the compile-time capacity. */
static ngx_uint_t   xrootd_session_registry_nslots =
    XROOTD_SESSION_REGISTRY_SLOTS;

/* Per-process pointer to the SHM session table (NULL until the zone is set up). */
static xrootd_session_table_t *
session_table(void)
{
    if (xrootd_session_shm_zone == NULL
        || xrootd_session_shm_zone->data == NULL
        || xrootd_session_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_session_table_t *) xrootd_session_shm_zone->data;
}

/* Shared-memory zone init callback: lay the session table out in the zone and
 * create its spin+yield mutex.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t
xrootd_session_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t               fresh;
    xrootd_session_table_t  *tbl;

    /*
     * Allocate the table FROM the slab pool (never lay it over shm.addr) so
     * nginx's ngx_unlock_mutexes() — which treats every zone's shm.addr as an
     * ngx_slab_pool_t header on every child death — does not get clobbered and
     * SIGSEGV the master. The helper handles fresh-alloc, reload (data != NULL),
     * and re-attach, creates xrootd_session_mutex from the table's leading
     * ngx_shmtx_sh_t lock, and publishes the table via shm_zone->data.
     */
    tbl = xrootd_shm_table_alloc(shm_zone, data,
                                 sizeof(xrootd_session_table_t)
                                 + (size_t) xrootd_session_registry_nslots
                                   * sizeof(xrootd_session_entry_t),
                                 &xrootd_session_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        tbl->capacity = xrootd_session_registry_nslots;
    }

    return NGX_OK;
}

/* Config-time setup of the session-registry SHM zone sized for `slots` entries.
 * Returns NGX_OK / NGX_ERROR. */
ngx_int_t
xrootd_configure_session_registry(ngx_conf_t *cf, ngx_uint_t slots)
{
    ngx_str_t  zone_name = ngx_string("xrootd_sessions");
    ngx_str_t  handle_zone_name = ngx_string("xrootd_session_handles");
    size_t     zone_size;

    if (slots == 0) {
        slots = XROOTD_SESSION_REGISTRY_SLOTS;
    }
    xrootd_session_registry_nslots = slots;

    zone_size = xrootd_shm_zone_size(sizeof(xrootd_session_table_t)
                + (size_t) slots * sizeof(xrootd_session_entry_t));
    xrootd_session_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                     zone_size,
                                                     &ngx_stream_xrootd_module);
    if (xrootd_session_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_shm_zone_warn_on_resize(cf, xrootd_session_shm_zone,
                                   "xrootd_session_slots");

    xrootd_session_shm_zone->init = xrootd_session_shm_init_zone;
    xrootd_session_shm_zone->data = (void *) 1;

    zone_size = xrootd_shm_zone_size(sizeof(xrootd_shared_handle_table_t));
    xrootd_handle_shm_zone = ngx_shared_memory_add(cf, &handle_zone_name,
                                                   zone_size,
                                                   &ngx_stream_xrootd_module);
    if (xrootd_handle_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_handle_shm_zone->init = xrootd_handle_shm_init_zone;
    xrootd_handle_shm_zone->data = (void *) 1;

    return NGX_OK;
}

/* Store a session's metadata (sessid, DN, VO list, token_auth) in the first free
 * SHM slot at login completion; a no-op if the sessid is already present.
 * Mutex-protected (cross-worker). */
void
xrootd_session_register(const u_char sessid[XROOTD_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth)
{
    xrootd_session_table_t *tbl;
    xrootd_session_entry_t *e;
    ngx_uint_t              i, free_slot, lru_slot;
    ngx_msec_t              now, lru_seen = 0;
    int                     found, reaped = 0;
    u_char                  victim[XROOTD_SESSION_ID_LEN];

    tbl = session_table();
    if (tbl == NULL) {
        return;
    }

    now = ngx_current_msec;

    ngx_shmtx_lock(&xrootd_session_mutex);

    free_slot = tbl->capacity;
    lru_slot  = tbl->capacity;
    found     = 0;

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            if (free_slot == tbl->capacity) {
                free_slot = i;
            }
            continue;
        }
        if (ngx_memcmp(e->sessid, sessid, XROOTD_SESSION_ID_LEN) == 0) {
            e->last_seen = now;        /* refresh activity on re-register */
            found = 1;
            break;
        }
        /* Track the global-LRU occupied slot for reap-on-full (F4). */
        if (lru_slot == tbl->capacity || e->last_seen < lru_seen) {
            lru_slot = i;
            lru_seen = e->last_seen;
        }
    }

    /* Phase 27 F4: when the table is full, reap the least-recently-seen slot
     * if it is older than the minimum reap age, so a slot-exhaustion attacker
     * cannot permanently deny new logins.  Otherwise reject (and count it). */
    if (!found && free_slot == tbl->capacity) {
        if (lru_slot < tbl->capacity
            && (now - lru_seen) >= XROOTD_SESSION_REAP_MIN_AGE_MS)
        {
            ngx_memcpy(victim, tbl->slots[lru_slot].sessid,
                       XROOTD_SESSION_ID_LEN);
            ngx_memzero(&tbl->slots[lru_slot], sizeof(tbl->slots[lru_slot]));
            free_slot = lru_slot;
            reaped = 1;
        } else {
            ngx_xrootd_metrics_t *m = xrootd_metrics_shared();
            if (m != NULL) {
                (void) ngx_atomic_fetch_add(&m->session_registry_full_total, 1);
            }
        }
    }

    if (!found && free_slot < tbl->capacity) {
        e = &tbl->slots[free_slot];
        ngx_memcpy(e->sessid, sessid, XROOTD_SESSION_ID_LEN);
        ngx_cpystrn((u_char *) e->dn, (u_char *) (dn ? dn : ""),
                    sizeof(e->dn));
        ngx_cpystrn((u_char *) e->vo_list,
                    (u_char *) (vo_list ? vo_list : ""),
                    sizeof(e->vo_list));
        e->token_auth = token_auth;
        e->last_seen  = now;
        e->in_use     = 1;
    }

    ngx_shmtx_unlock(&xrootd_session_mutex);

    /* Unpublish the reaped victim's handles AFTER releasing the session mutex
     * (mirrors xrootd_session_unregister's lock order: session then handle). */
    if (reaped) {
        ngx_xrootd_metrics_t *m = xrootd_metrics_shared();
        if (m != NULL) {
            (void) ngx_atomic_fetch_add(&m->session_evict_total, 1);
        }
        xrootd_session_handle_unpublish_all(victim);
    }
}

/* Look a session up by sessid, copying its DN / VO list / token_auth out (used
 * by kXR_bind secondaries and proxy mode).  Returns 1 on hit, 0 on miss.
 * Mutex-protected. */
int
xrootd_session_lookup(const u_char sessid[XROOTD_SESSION_ID_LEN],
    char *dn_out, size_t dn_size,
    char *vo_out, size_t vo_size,
    ngx_uint_t *token_auth_out)
{
    xrootd_session_table_t *tbl;
    xrootd_session_entry_t *e;
    ngx_uint_t              i;
    int                     found = 0;

    tbl = session_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&xrootd_session_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        if (ngx_memcmp(e->sessid, sessid, XROOTD_SESSION_ID_LEN) == 0) {
            ngx_cpystrn((u_char *) dn_out, (u_char *) e->dn, dn_size);
            ngx_cpystrn((u_char *) vo_out, (u_char *) e->vo_list, vo_size);
            *token_auth_out = e->token_auth;
            e->last_seen = ngx_current_msec;  /* F4: activity keeps it off the LRU */
            found = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_session_mutex);
    return found;
}

/* Clear a session's SHM slot at kXR_endsess / disconnect and unpublish all of
 * its handles.  Mutex-protected. */
void
xrootd_session_unregister(const u_char sessid[XROOTD_SESSION_ID_LEN])
{
    xrootd_session_table_t *tbl;
    xrootd_session_entry_t *e;
    ngx_uint_t              i;

    tbl = session_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_session_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (e->in_use
            && ngx_memcmp(e->sessid, sessid, XROOTD_SESSION_ID_LEN) == 0)
        {
            ngx_memzero(e, sizeof(*e));
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_session_mutex);
    xrootd_session_handle_unpublish_all(sessid);
}
