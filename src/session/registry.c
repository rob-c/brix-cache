/* ------------------------------------------------------------------ */
/* Session Registry — Shared Memory Cross-Worker Coordination             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the shared memory session registry and handle table — critical infrastructure enabling cross-worker process coordination for XRootD sessions in nginx deployments with multiple worker processes. Two shared memory zones exist: xrootd_sessions (session registry) storing client session metadata including sessid, DN (distinguished name), VO list, and token_auth flag; and xrootd_session_handles (handle table) publishing file handle information so bound stream secondary connections can access primary-published handles without requiring the primary connection's worker process to be active.
 *
 * WHY: In nginx deployments with multiple worker processes (configured via worker_processes directive), each worker runs independently — a client session may be handled by one worker while subsequent requests arrive at different workers. Shared memory registry enables all workers to access session metadata regardless of which worker originally established the connection, ensuring consistent authentication state across worker boundaries. Handle publishing enables bound stream secondary connections (established via kXR_bind) to read primary-published handles even when those handles were opened by a different worker process — critical for parallel data transfer scenarios where xrdcp establishes multiple TCP channels across workers.
 *
 * HOW: Three-layer coordination → shared memory zone initialization during postconfiguration phase (ngx_shared_memory_add creating zones with ngx_pagesize overhead + table struct capacity) — mutex creation per zone (ngx_shmtx_create ensuring thread-safe cross-worker access) — session lifecycle operations (registration via slot scan finding free entry, lookup via sessid comparison across all slots, unregistration via memzero clearing entry and unpublishing associated handles); handle lifecycle operations (publishing readable/writable metadata for bound stream access, lookup by sessid+handle_index key matching, unpublish on close or session termination). All operations locked with zone-specific mutex before accessing shared memory to prevent concurrent modification race conditions. */

/* ------------------------------------------------------------------ */
/* Section: Shared Memory Zone Initialization                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_configure_session_registry() creates two shared memory zones during nginx postconfiguration phase. First zone (xrootd_sessions): size = sizeof(xrootd_session_table_t) + ngx_pagesize providing session registry capacity with page-size overhead for alignment; second zone (xrootd_session_handles): size = sizeof(xrootd_shared_handle_table_t) + ngx_pagesize providing handle table capacity. Each zone registers an init callback function that allocates mutex locks and initializes table structures when the zone is first mapped by any worker process.
 *
 * WHY: Shared memory enables cross-worker session persistence — without it, sessions established by one worker would be invisible to subsequent requests arriving at different workers, causing authentication failures or duplicate session creation attempts. Page-size overhead ensures proper memory alignment preventing cache line interference between worker processes accessing the same shared region. Init callbacks use (void *) 1 sentinel value indicating zone already initialized by another worker — prevents double-initialization race conditions when multiple workers start simultaneously. */

/* ------------------------------------------------------------------ */
/* Section: Session Registry Lifecycle                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_session_register() stores client session metadata in shared memory registry slot during login completion (anonymous mode or after kXR_auth). Scans all XROOTD_SESSION_REGISTRY_SLOTS entries finding first free slot (e->in_use==0) — if sessid already exists returns silently, otherwise copies sessid[16], dn, vo_list, and token_auth flag into new slot setting e->in_use=1. xrootd_session_lookup() retrieves session metadata for bound stream secondary connections or proxy mode — scans all slots comparing sessid via ngx_memcmp returning DN/VO list/token_auth if match found. xrootd_session_unregister() clears session entry during kXR_endsess or disconnect cleanup, additionally unpublishing all associated handles via xrootd_session_handle_unpublish_all().
 *
 * WHY: Session registry enables consistent authentication state across worker boundaries — bound stream connections and proxy forwarding require access to session metadata regardless of which worker originally handled login. DN (distinguished name from GSI certificate) and VO list determine authorization eligibility; token_auth flag indicates whether JWT bearer token was used instead of GSI certificate, enabling different auth gate enforcement paths. Unregister clears both session entry and all associated published handles ensuring no stale handle references remain after session termination preventing security issues where bound streams could access closed primary handles. */

/* ------------------------------------------------------------------ */
/* Section: Handle Table Publishing                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_session_handle_publish() shares file handle metadata with other workers enabling bound stream secondary connections to read primary-published handles. Validates handle_index (0–255 range) and file state (fd must be valid, readable=true required for publishing, path must exist); searches handle table slots finding matching sessid+handle_index key or free slot; copies readable/writable/from_cache/is_regular/device/inode/cached_size/path metadata into entry setting e->in_use=1. Write-only handles are rejected from publishing (security: prevents bound stream misuse of write channels). xrootd_session_handle_lookup() retrieves published handle metadata for bound stream read requests — searches slots by sessid+handle_index key matching returning copy of entry if found.
 *
 * WHY: Handle publishing enables parallel data transfer across worker boundaries — xrdcp secondary connections established via kXR_bind may arrive at different workers than primary connection, requiring access to primary-published handle metadata without needing primary worker's active session context. Publishing only readable handles prevents security issues where bound streams could misuse write channels (bound streams are read-only data channels per design). Device/inode/cached_size metadata enables bound stream reads to verify file identity against original open parameters preventing stale reference attacks where published handles could be reused after file modification or deletion. */

/* ------------------------------------------------------------------ */
/* Section: Handle Unpublishing                                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_session_handle_unpublish() removes individual handle entry from shared table during kXR_close — searches slots by sessid+handle_index key matching, memzeros entry clearing all metadata. xrootd_session_handle_unpublish_all() removes all handles associated with specific sessid during session termination (kXR_endsess or disconnect cleanup) — scans all in_use entries comparing sessid, memzeros matching entries ensuring no stale handle references remain after session end.
 *
 * WHY: Handle unpublishing ensures bound stream secondary connections cannot access primary-published handles after those handles are closed — prevents security issues where bound streams could continue reading files that were supposed to be terminated by the primary connection. Unpublish all during session termination clears every published handle for that sessid regardless of which worker originally published each handle, ensuring complete cleanup across all workers without requiring per-handle coordination. */

/* ---- Function: xrootd_configure_session_registry() ----
 *
 * WHAT: Creates two shared memory zones during nginx postconfiguration phase enabling cross-worker session persistence and handle publishing. First zone (xrootd_sessions): size = sizeof(xrootd_session_table_t) + ngx_pagesize providing session registry capacity with page-size overhead for alignment; second zone (xrootd_session_handles): size = sizeof(xrootd_shared_handle_table_t) + ngx_pagesize providing handle table capacity. Each zone registers init callback function that allocates mutex locks and initializes table structures when first mapped by any worker process. Sentinel value (void *) 1 indicates zone already initialized — prevents double-initialization race conditions when multiple workers start simultaneously.
 *
 * WHY: Shared memory enables cross-worker session persistence — without it, sessions established by one worker would be invisible to subsequent requests arriving at different workers, causing authentication failures or duplicate session creation attempts. Page-size overhead ensures proper memory alignment preventing cache line interference between worker processes accessing the same shared region. Init callbacks use sentinel value indicating zone already initialized by another worker — prevents double-initialization race conditions when multiple workers start simultaneously.
 *
 * HOW: Two-zone creation → configure xrootd_sessions zone (sizeof(table) + ngx_pagesize overhead, init=xrootd_session_shm_init_zone, data=(void *) 1 sentinel) — configure xrootd_session_handles zone (sizeof(table) + ngx_pagesize overhead, init=xrootd_handle_shm_init_zone, data=(void *) 1 sentinel) — return NGX_OK if both zones created successfully, NGX_ERROR otherwise. */

/* ---- Function: xrootd_session_register() ----
 *
 * WHAT: Stores client session metadata in shared memory registry slot during login completion (anonymous mode or after kXR_auth). Scans all XROOTD_SESSION_REGISTRY_SLOTS entries finding first free slot (e->in_use==0) — if sessid already exists returns silently, otherwise copies sessid[16], dn (distinguished name from GSI certificate), vo_list (virtual organization authorization list), and token_auth flag into new slot setting e->in_use=1. Protected by xrootd_session_mutex lock ensuring thread-safe cross-worker access during concurrent registration attempts.
 *
 * WHY: Session registry enables consistent authentication state across worker boundaries — bound stream connections and proxy forwarding require access to session metadata regardless of which worker originally handled login. DN (distinguished name from GSI certificate) and VO list determine authorization eligibility; token_auth flag indicates whether JWT bearer token was used instead of GSI certificate, enabling different auth gate enforcement paths. Mutex protection prevents race conditions during concurrent registration attempts when multiple workers may simultaneously attempt to register overlapping sessions.
 *
 * HOW: Two-phase registration → scan all slots finding free slot (e->in_use==0) while tracking first available and checking for existing sessid match — if sessid exists returns silently; otherwise copy sessid[16], dn, vo_list, token_auth into new slot setting e->in_use=1 — unlock xrootd_session_mutex after completion. */

/* ---- Function: xrootd_session_lookup() ----
 *
 * WHAT: Retrieves session metadata for bound stream secondary connections or proxy mode — scans all XROOTD_SESSION_REGISTRY_SLOTS entries comparing sessid via ngx_memcmp returning DN/VO list/token_auth if match found. Called by kXR_bind handler to inherit authentication state from primary session, and by proxy forwarding code to determine auth gate enforcement path based on token_auth flag. Protected by xrootd_session_mutex lock ensuring thread-safe cross-worker access during concurrent lookup attempts.
 *
 * WHY: Session lookup enables consistent authentication state across worker boundaries — bound stream connections established via kXR_bind require access to session metadata regardless of which worker originally handled login, enabling secondary connections to inherit logged_in/auth_done=1 from primary session registry entry. Proxy forwarding code uses token_auth flag to determine whether JWT bearer token or GSI certificate was used, enabling different auth gate enforcement paths for subsequent operations. Mutex protection prevents race conditions during concurrent lookup attempts when multiple workers may simultaneously access the same session entry.
 *
 * HOW: Two-phase lookup → scan all slots comparing sessid via ngx_memcmp finding matching entry — if found copy dn/vo_list/token_auth into output parameters returning 1; otherwise return 0 indicating no match — unlock xrootd_session_mutex after completion. */

/* ---- Function: xrootd_session_handle_publish() ----
 *
 * WHAT: Shares file handle metadata with other workers enabling bound stream secondary connections to read primary-published handles. Validates handle_index (0–255 range) and file state (fd must be valid, readable=true required for publishing, path must exist); searches handle table slots finding matching sessid+handle_index key or free slot; copies readable/writable/from_cache/is_regular/device/inode/cached_size/path metadata into entry setting e->in_use=1. Write-only handles are rejected from publishing (security: prevents bound stream misuse of write channels). Protected by xrootd_handle_mutex lock ensuring thread-safe cross-worker access during concurrent publishing attempts.
 *
 * WHY: Handle publishing enables parallel data transfer across worker boundaries — xrdcp secondary connections established via kXR_bind may arrive at different workers than primary connection, requiring access to primary-published handle metadata without needing primary worker's active session context. Publishing only readable handles prevents security issues where bound streams could misuse write channels (bound streams are read-only data channels per design). Device/inode/cached_size metadata enables bound stream reads to verify file identity against original open parameters preventing stale reference attacks where published handles could be reused after file modification or deletion.
 *
 * HOW: Three-phase publishing → validate handle_index (0–255) and file state (fd>=0, readable=true required for publishing, path exists) — search slots finding matching sessid+handle_index key via xrootd_shared_handle_same_key() or free slot — if entry found memzero before updating; otherwise allocate free slot — copy readable/writable/from_cache/is_regular/device/inode/cached_size/path metadata into entry setting e->in_use=1 — unlock xrootd_handle_mutex after completion. Write-only handles rejected from publishing preventing bound stream misuse of write channels. */

/* ---- Function: xrootd_session_handle_lookup() ----
 *
 * WHAT: Retrieves published handle metadata for bound stream read requests — searches slots by sessid+handle_index key matching via xrootd_shared_handle_same_key() returning copy of entry if found. Called by bound stream secondary connections to access primary-published handles when those handles were opened by a different worker process. Returns 1 on success with out populated, 0 indicating no published handle found for requested sessid+handle_index combination. Protected by xrootd_handle_mutex lock ensuring thread-safe cross-worker access during concurrent lookup attempts.
 *
 * WHY: Handle lookup enables bound stream secondary connections to read primary-published handles regardless of which worker originally opened the file — critical for parallel data transfer scenarios where xrdcp establishes multiple TCP channels across workers requiring consistent handle metadata access. Device/inode/cached_size metadata enables bound stream reads to verify file identity against original open parameters preventing stale reference attacks where published handles could be reused after file modification or deletion.
 *
 * HOW: Two-phase lookup → validate handle_index (0–255) and out pointer — search slots by sessid+handle_index key matching via xrootd_shared_handle_same_key() — if match found copy entry into out parameter with path null-termination ensuring safe string access returning 1; otherwise return 0 indicating no published handle found — unlock xrootd_handle_mutex after completion. */

/* ---- Function: xrootd_session_handle_unpublish() ----
 *
 * WHAT: Removes individual handle entry from shared table during kXR_close — searches slots by sessid+handle_index key matching via xrootd_shared_handle_same_key(), memzeros entry clearing all metadata preventing bound stream access to closed primary handles. Called after every file close operation ensuring no stale published references remain after session end. Protected by xrootd_handle_mutex lock ensuring thread-safe cross-worker access during concurrent unpublish attempts.
 *
 * WHY: Handle unpublishing ensures bound stream secondary connections cannot access primary-published handles after those handles are closed — prevents security issues where bound streams could continue reading files that were supposed to be terminated by the primary connection. Individual unpublish removes specific handle reference; xrootd_session_handle_unpublish_all() clears every published handle for that sessid during session termination ensuring complete cleanup across all workers without requiring per-handle coordination.
 *
 * HOW: Two-phase unpublish → validate handle_index (0–255) — search slots by sessid+handle_index key matching via xrootd_shared_handle_same_key() — if match found memzero entry clearing all metadata returning no published reference for bound stream access attempts — unlock xrootd_handle_mutex after completion. */

/* ---- Function: xrootd_session_handle_unpublish_all() ----
 *
 * WHAT: Removes all handles associated with specific sessid during session termination (kXR_endsess or disconnect cleanup) — scans all in_use entries comparing sessid, memzeros matching entries ensuring no stale handle references remain after session end. Called by kXR_endsess handler and xrootd_session_unregister() to ensure complete cross-worker cleanup of published handles regardless of which worker originally published each handle. Protected by xrootd_handle_mutex lock ensuring thread-safe cross-worker access during concurrent unpublish-all attempts.
 *
 * WHY: Complete unpublish all ensures bound stream secondary connections cannot access any primary-published handles after session termination — prevents security issues where bound streams could continue reading files that were supposed to be terminated by the primary connection. Unpublish all during session termination clears every published handle for that sessid regardless of which worker originally published each handle, ensuring complete cleanup across all workers without requiring per-handle coordination. Session unregister additionally calls this function after clearing session entry ensuring coordinated cleanup of both session metadata and associated handles.
 *
 * HOW: Two-phase unpublish-all → scan all in_use entries comparing sessid via ngx_memcmp — if match found memzero entry clearing all metadata returning no published reference for bound stream access attempts — unlock xrootd_handle_mutex after completion. Called by kXR_endsess handler and xrootd_session_unregister() to ensure complete cross-worker cleanup of published handles regardless of which worker originally published each handle. */

/* ---- Function: xrootd_session_unregister() ----
 *
 * WHAT: Clears session entry during kXR_endsess or disconnect cleanup — scans all XROOTD_SESSION_REGISTRY_SLOTS entries comparing sessid, memzeros matching entry clearing session metadata; additionally calls xrootd_session_handle_unpublish_all() to clear every published handle for that sessid ensuring coordinated cleanup of both session metadata and associated handles. Called by kXR_endsess handler and xrootd_on_disconnect() during session termination ensuring complete cross-worker cleanup regardless of which worker originally registered the session. Protected by xrootd_session_mutex lock ensuring thread-safe cross-worker access during concurrent unregistration attempts.
 *
 * WHY: Session unregister ensures bound stream secondary connections cannot access any primary-published handles after session termination — prevents security issues where bound streams could continue reading files that were supposed to be terminated by the primary connection. Unregister clears both session entry and all associated published handles ensuring no stale references remain after session end preventing security issues where bound streams could access closed primary handles or use stale session metadata for unauthorized operations.
 *
 * HOW: Two-phase unregister → scan all entries comparing sessid via ngx_memcmp — if match found memzero entry clearing session metadata returning no registry reference for subsequent operations — additionally call xrootd_session_handle_unpublish_all() to clear every published handle for that sessid ensuring coordinated cleanup of both session metadata and associated handles — unlock xrootd_session_mutex after completion. */

#include "registry.h"
#include "../compat/shm_slots.h"
#include <ngx_shmtx.h>
#include <string.h>

ngx_shm_zone_t *xrootd_session_shm_zone;
ngx_shm_zone_t *xrootd_handle_shm_zone;

static ngx_shmtx_t  xrootd_session_mutex;

/* Runtime slot count for the session registry (xrootd_session_slots);
 * defaults to the compile-time capacity. */
static ngx_uint_t   xrootd_session_registry_nslots =
    XROOTD_SESSION_REGISTRY_SLOTS;

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
