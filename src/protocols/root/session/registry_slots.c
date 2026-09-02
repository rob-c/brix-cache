/*
 * registry_slots.c — slot mechanics for the SHM session registry.
 *
 * The per-slot helpers behind registry.c's public API: the per-source quota
 * key (W5/P90-27.2), the single-pass table scan, F4 global-LRU reap,
 * slot fill, locked find, per-source self-eviction, and the post-unlock
 * eviction tail. None of these lock — registry.c holds brix_session_mutex
 * around each call (finish_eviction runs after release by design).
 */

#include "registry_slots_internal.h"
#include "net/ratelimit/ratelimit.h"   /* brix_rl_key_{dn,sub}_hash (W5 quota key) */
#include <string.h>

/* ---- Per-source quota key for one registrant (W5 / P90-27.2) --------------
 *
 * WHAT: Renders the registrant's ratelimit-vocabulary bucket id into `out`
 * (BRIX_SESSION_SRC_KEY_LEN bytes): "sub:<8-hex>" for token logins,
 * "dn:<8-hex>" for certificate/system logins, "" when the login carried no DN
 * (un-keyed — such sessions are exempt from the per-source cap and only ever
 * subject to the F4 global LRU, exactly the pre-W5 regime).
 *
 * WHY: The registry only receives (dn, token_auth), not the full connection
 * ctx, so the key is derived here from the same identity string every caller
 * already passes — via the SHARED brix_rl_key_* formatters, so one principal
 * maps to the same no-PII bucket id in the limiter and in this quota. */
void
brix_session_src_key(const char *dn, ngx_uint_t token_auth,
    char out[BRIX_SESSION_SRC_KEY_LEN])
{
    out[0] = '\0';
    if (dn == NULL || dn[0] == '\0') {
        return;
    }
    if (token_auth) {
        brix_rl_key_sub_hash((const u_char *) dn, ngx_strlen(dn),
                             out, BRIX_SESSION_SRC_KEY_LEN);
    } else {
        brix_rl_key_dn_hash((const u_char *) dn, ngx_strlen(dn),
                            out, BRIX_SESSION_SRC_KEY_LEN);
    }
}

/* ---- Scan the session table for a sessid, tracking free/LRU/quota slots ----
 *
 * WHAT: Walks every occupied slot looking for `sessid`.  On a hit it refreshes
 * that slot's last_seen to `now` and returns 1.  On a miss it returns 0 with
 * `sc` reporting the first free slot, the global-LRU occupied slot (F4
 * reap-on-full), and — when `src_key` is non-empty — how many slots the
 * registrant already owns plus its own-LRU slot (W5 per-source quota).
 *
 * WHY: Isolates the single linear pass over the SHM table so the caller stays a
 * flat sequence of decisions.  Must run with brix_session_mutex held — it reads
 * and (on a hit) writes shared slot state.
 *
 * HOW:
 *   1. Seed `sc` to its empty-table defaults.
 *   2. For each slot: record the first free one and skip it.
 *   3. On a sessid match, stamp last_seen and return 1.
 *   4. Otherwise fold the occupied slot into the global LRU minimum, and — on
 *      a src_key match — into the registrant's own count + own-LRU minimum.
 *   5. Return 0 if no slot matched.
 */
int
brix_session_scan(brix_session_table_t *tbl,
    const u_char sessid[BRIX_SESSION_ID_LEN], ngx_msec_t now,
    const char *src_key, brix_session_scan_t *sc)
{
    brix_session_entry_t *e;
    ngx_uint_t              i;

    sc->free_slot    = tbl->capacity;
    sc->lru_slot     = tbl->capacity;
    sc->lru_seen     = 0;
    sc->src_count    = 0;
    sc->src_lru_slot = tbl->capacity;
    sc->src_lru_seen = 0;

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            if (sc->free_slot == tbl->capacity) {
                sc->free_slot = i;
            }
            continue;
        }
        if (ngx_memcmp(e->sessid, sessid, BRIX_SESSION_ID_LEN) == 0) {
            e->last_seen = now;        /* refresh activity on re-register */
            return 1;
        }
        /* Track the global-LRU occupied slot for reap-on-full (F4). */
        if (sc->lru_slot == tbl->capacity || e->last_seen < sc->lru_seen) {
            sc->lru_slot = i;
            sc->lru_seen = e->last_seen;
        }
        /* Track the registrant's OWN slot count + own-LRU (W5 quota). */
        if (src_key[0] != '\0' && ngx_strcmp(e->src_key, src_key) == 0) {
            sc->src_count++;
            if (sc->src_lru_slot == tbl->capacity
                || e->last_seen < sc->src_lru_seen)
            {
                sc->src_lru_slot = i;
                sc->src_lru_seen = e->last_seen;
            }
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
int
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
void
brix_session_fill_slot(brix_session_table_t *tbl, ngx_uint_t slot,
    const u_char sessid[BRIX_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth,
    const char *src_key, ngx_msec_t now)
{
    brix_session_entry_t *e = &tbl->slots[slot];

    ngx_memcpy(e->sessid, sessid, BRIX_SESSION_ID_LEN);
    ngx_cpystrn((u_char *) e->dn, (u_char *) (dn ? dn : ""), sizeof(e->dn));
    ngx_cpystrn((u_char *) e->vo_list, (u_char *) (vo_list ? vo_list : ""),
                sizeof(e->vo_list));
    ngx_cpystrn((u_char *) e->src_key, (u_char *) src_key,
                sizeof(e->src_key));
    e->token_auth = token_auth;
    e->last_seen  = now;
    e->in_use     = 1;
    /* §1.4: the registering worker owns the primary connection — a kXR_bind
     * arriving on any OTHER worker migrates its secondary here (bind_migrate.c). */
    e->owner_worker = (ngx_int_t) ngx_worker;
    /* A recycled slot must not inherit the previous session's bound paths. */
    ngx_memzero(e->pathid_map, sizeof(e->pathid_map));
}

/* ---- Locate a live slot by sessid (registry mutex held) ----
 *
 * WHAT: Returns the in-use entry whose sessid matches, or NULL.
 *
 * WHY: The three pathid-bitmap operations share this scan; keeping it a
 *      helper keeps each public function a flat lock→find→bit-op→unlock
 *      sequence.
 *
 * HOW: Linear scan to capacity, ngx_memcmp on the 16-byte id.
 */
brix_session_entry_t *
brix_session_find_locked(brix_session_table_t *tbl,
    const u_char sessid[BRIX_SESSION_ID_LEN])
{
    brix_session_entry_t *slots = tbl->slots;
    ngx_uint_t            i, capacity = tbl->capacity;

    for (i = 0; i < capacity; i++) {
        if (slots[i].in_use
            && ngx_memcmp(slots[i].sessid, sessid,
                          BRIX_SESSION_ID_LEN) == 0)
        {
            return &slots[i];
        }
    }
    return NULL;
}


/* ---- Self-evict an over-quota identity's own LRU slot (W5 / P90-27.2) -----
 *
 * WHAT: Invoked when the registrant already owns >= the per-source soft cap of
 * live slots.  Snapshots the registrant's OWN least-recently-seen session into
 * `victim`, clears that slot, publishes its index via `free_slot_out`, bumps
 * the src-cap metric, and returns 1.  Returns 0 (nothing evicted) if the scan
 * found no own-LRU slot (defensive; count >= cap implies one exists).
 *
 * WHY: The soft cap must bite BEFORE free-slot consumption and BEFORE the F4
 * global reap: an over-quota identity recycles its own sessions, so it can
 * neither fill the table nor pressure OTHER identities' slots.  Only the
 * over-quota principal pays — its oldest session dies, everyone else is
 * untouched.  No minimum-age gate (unlike F4): self-eviction harms no third
 * party, and an identity churning through its own quota is exactly the
 * behaviour the cap exists to bound.  Must run with brix_session_mutex held.
 */
int
brix_session_src_cap_evict(brix_session_table_t *tbl,
    ngx_uint_t src_lru_slot, ngx_uint_t *free_slot_out,
    u_char victim[BRIX_SESSION_ID_LEN])
{
    ngx_brix_metrics_t *m;

    if (src_lru_slot >= tbl->capacity) {
        return 0;
    }

    ngx_memcpy(victim, tbl->slots[src_lru_slot].sessid, BRIX_SESSION_ID_LEN);
    ngx_memzero(&tbl->slots[src_lru_slot], sizeof(tbl->slots[src_lru_slot]));
    *free_slot_out = src_lru_slot;

    m = brix_metrics_shared();
    if (m != NULL) {
        (void) ngx_atomic_fetch_add(&m->session_src_cap_evict_total, 1);
    }
    return 1;
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
void
brix_session_finish_eviction(const u_char victim[BRIX_SESSION_ID_LEN])
{
    ngx_brix_metrics_t *m = brix_metrics_shared();

    if (m != NULL) {
        (void) ngx_atomic_fetch_add(&m->session_evict_total, 1);
    }
    brix_session_handle_unpublish_all(victim);
}


