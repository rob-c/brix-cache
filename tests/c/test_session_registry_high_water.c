/*
 * test_session_registry_high_water.c — unit tests for the live-prefix mark on
 * the SHM session registry (src/protocols/root/session/registry_slots.c).
 *
 * WHY THIS EXISTS: brix_session_scan and brix_session_find_locked used to walk
 * all `capacity` slots on every login and every disconnect, under the single
 * cross-worker session mutex — so an almost-empty table cost exactly as much as
 * a full one, and the default 1024 slots taxed every FTS-shaped connection
 * twice.  high_water bounds each walk to the live prefix.  The optimization is
 * only sound while ONE invariant holds:
 *
 *     every in_use slot has index < high_water
 *
 * If that ever breaks, a scan silently stops short of an occupied slot — and
 * the two DEFENCES built on the scan (the W5 per-source quota and the F4
 * global-LRU reap) would under-count, which is a security regression, not a
 * performance one.  The security-negative battery below attacks exactly that.
 *
 * Links the real registry_slots.o.  Its cross-TU symbols (the two ratelimit key
 * formatters, the metrics accessor, the handle-table unpublish and ngx_worker)
 * are supplied here as spies, so the battery stays hermetic.
 *
 * Build/run via cmdscripts/c_object_units.py (SPECS["session_registry_high_water"]),
 * surfaced by tests/test_c_object_units.py, which parametrizes over SPECS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocols/root/session/registry_slots_internal.h"

static int g_pass, g_fail;
#define CHECK(cond, msg) do {                                               \
        if (cond) { g_pass++; }                                             \
        else { g_fail++; fprintf(stderr, "FAIL: %s (%s:%d)\n",              \
                                  msg, __FILE__, __LINE__); }               \
    } while (0)

/* ---- spies for registry_slots.o's cross-TU closure ---------------------- */

ngx_uint_t ngx_worker;

/* brix_metrics_shared() is a static inline over this zone pointer and returns
 * NULL while it is unset, so leaving the metrics plane down is all it takes:
 * every counter site under test is NULL-guarded, and the reap/evict paths run
 * their real logic while skipping only the counter. */
ngx_shm_zone_t *ngx_brix_shm_zone = NULL;

static int g_unpublish_calls;

void
brix_session_handle_unpublish_all(const u_char sessid[BRIX_SESSION_ID_LEN])
{
    (void) sessid;
    g_unpublish_calls++;
}

/* The real formatters hash to a no-PII bucket id; for the quota tests all that
 * matters is that equal identities produce equal keys and different identities
 * produce different ones, so a bounded copy of the input is a faithful spy. */
static void
key_spy(const u_char *data, size_t len, char *out, size_t out_len, char tag)
{
    size_t n = len;

    if (n > out_len - 3) {
        n = out_len - 3;
    }
    out[0] = tag;
    out[1] = ':';
    memcpy(out + 2, data, n);
    out[2 + n] = '\0';
}

void
brix_rl_key_sub_hash(const u_char *data, size_t len, char *out, size_t out_len)
{
    key_spy(data, len, out, out_len, 's');
}

void
brix_rl_key_dn_hash(const u_char *data, size_t len, char *out, size_t out_len)
{
    key_spy(data, len, out, out_len, 'd');
}

/* ---- table helpers ------------------------------------------------------ */

static brix_session_table_t *
mktable(ngx_uint_t capacity)
{
    brix_session_table_t *tbl;
    size_t bytes = sizeof(*tbl) + (size_t) capacity * sizeof(tbl->slots[0]);

    tbl = malloc(bytes);
    if (tbl == NULL) {
        fprintf(stderr, "FAIL: out of memory\n");
        exit(1);
    }
    memset(tbl, 0, bytes);          /* mirrors the SHM zone's fresh memzero */
    tbl->capacity = capacity;
    return tbl;
}

static void
mksess(u_char out[BRIX_SESSION_ID_LEN], unsigned n)
{
    memset(out, 0, BRIX_SESSION_ID_LEN);
    out[0] = (u_char) (n & 0xff);
    out[1] = (u_char) ((n >> 8) & 0xff);
}

/* Register `sessid` under identity `dn` the way registry.c's
 * brix_session_register does: scan, then fill the slot the scan chose.
 * Returns the slot used, or `capacity` when the table had no room. */
static ngx_uint_t
reg(brix_session_table_t *tbl, unsigned n, const char *dn, ngx_msec_t now)
{
    brix_session_scan_t sc;
    u_char              sessid[BRIX_SESSION_ID_LEN];
    char                src_key[BRIX_SESSION_SRC_KEY_LEN];

    mksess(sessid, n);
    brix_session_src_key(dn, 0, src_key);

    if (brix_session_scan(tbl, sessid, now, src_key, &sc)) {
        return tbl->capacity;                   /* already present */
    }
    if (sc.free_slot >= tbl->capacity) {
        return tbl->capacity;                   /* full */
    }
    brix_session_fill_slot(tbl, sc.free_slot, sessid, dn, "", 0, src_key, now);
    return sc.free_slot;
}

/* Clear `sessid` the way brix_session_unregister does: find, zero, shrink. */
static int
unreg(brix_session_table_t *tbl, unsigned n)
{
    brix_session_entry_t *e;
    u_char                sessid[BRIX_SESSION_ID_LEN];

    mksess(sessid, n);
    e = brix_session_find_locked(tbl, sessid);
    if (e == NULL) {
        return 0;
    }
    memset(e, 0, sizeof(*e));
    brix_session_shrink(tbl);
    return 1;
}

/* THE invariant the whole optimization rests on. */
static int
prefix_covers_every_live_slot(brix_session_table_t *tbl)
{
    ngx_uint_t i;

    for (i = tbl->high_water; i < tbl->capacity; i++) {
        if (tbl->slots[i].in_use) {
            return 0;
        }
    }
    return 1;
}

static ngx_uint_t
live_count(brix_session_table_t *tbl)
{
    ngx_uint_t i, n = 0;

    for (i = 0; i < tbl->capacity; i++) {
        if (tbl->slots[i].in_use) {
            n++;
        }
    }
    return n;
}

/* ---- 1. success: the mark tracks the live prefix ------------------------ */

static void
test_success_prefix_tracking(void)
{
    brix_session_table_t *tbl = mktable(1024);
    u_char                sessid[BRIX_SESSION_ID_LEN];

    CHECK(tbl->high_water == 0, "fresh table has an empty live prefix");

    CHECK(reg(tbl, 1, "alice", 1000) == 0, "first login takes slot 0");
    CHECK(tbl->high_water == 1, "prefix grew to 1");
    CHECK(reg(tbl, 2, "bob", 1001) == 1, "second login takes slot 1");
    CHECK(reg(tbl, 3, "carol", 1002) == 2, "third login takes slot 2");
    CHECK(tbl->high_water == 3, "prefix grew to 3, NOT to capacity");

    /* The whole point: a 1024-slot table with 3 sessions scans 3 slots. */
    CHECK(tbl->high_water == live_count(tbl),
          "prefix equals the live population when there are no holes");

    /* Lookups still resolve inside the bounded walk. */
    mksess(sessid, 2);
    CHECK(brix_session_find_locked(tbl, sessid) == &tbl->slots[1],
          "find resolves a live session within the prefix");
    mksess(sessid, 99);
    CHECK(brix_session_find_locked(tbl, sessid) == NULL,
          "find misses an absent session");

    /* Disconnect retires the freed top run. */
    CHECK(unreg(tbl, 3) == 1, "unregister the top session");
    CHECK(tbl->high_water == 2, "prefix retired to 2");
    CHECK(unreg(tbl, 2) == 1, "unregister the new top session");
    CHECK(tbl->high_water == 1, "prefix retired to 1");
    CHECK(unreg(tbl, 1) == 1, "unregister the last session");
    CHECK(tbl->high_water == 0, "prefix retired to empty");
    CHECK(prefix_covers_every_live_slot(tbl), "invariant holds when empty");

    free(tbl);
}

/* ---- 2. error/boundary: holes, reuse, and a genuinely full table -------- */

static void
test_boundary_holes_and_full(void)
{
    brix_session_table_t *tbl = mktable(4);
    brix_session_scan_t   sc;
    u_char                sessid[BRIX_SESSION_ID_LEN];
    u_char                victim[BRIX_SESSION_ID_LEN];
    ngx_uint_t            free_slot;
    char                  src_key[BRIX_SESSION_SRC_KEY_LEN];

    (void) reg(tbl, 1, "alice", 1000);
    (void) reg(tbl, 2, "bob",   1001);
    (void) reg(tbl, 3, "carol", 1002);
    CHECK(tbl->high_water == 3, "three live, prefix 3");

    /* A hole in the MIDDLE must not retire the prefix: shrink stops at the
     * first occupied slot seen from the top. */
    CHECK(unreg(tbl, 2) == 1, "unregister the middle session");
    CHECK(tbl->high_water == 3,
          "a middle hole leaves the prefix at 3 (slot 2 is still live)");
    CHECK(prefix_covers_every_live_slot(tbl), "invariant holds with a hole");

    /* The hole is reused before the frontier is extended. */
    CHECK(reg(tbl, 4, "dave", 1003) == 1, "next login refills the hole");
    CHECK(tbl->high_water == 3, "refilling a hole does not grow the prefix");

    /* Fill the frontier, then the table is genuinely full. */
    CHECK(reg(tbl, 5, "erin", 1004) == 3, "fourth login takes the frontier");
    CHECK(tbl->high_water == 4, "prefix at capacity");

    mksess(sessid, 6);
    brix_session_src_key("frank", 0, src_key);
    CHECK(brix_session_scan(tbl, sessid, 1005, src_key, &sc) == 0,
          "a new sessid misses on a full table");
    CHECK(sc.free_slot == tbl->capacity,
          "a full table reports no free slot (never the frontier)");
    CHECK(sc.lru_slot < tbl->capacity,
          "a full table still nominates a global-LRU victim");

    /* F4 reap: the LRU slot is young here, so the reap must REFUSE. */
    CHECK(brix_session_reap_lru(tbl, 1005, sc.lru_slot, sc.lru_seen,
                                &free_slot, victim) == 0,
          "reap refuses a victim younger than the minimum age");
    CHECK(live_count(tbl) == 4, "refused reap evicted nobody");

    /* Aged past the floor, the same reap succeeds and frees that slot. */
    {
        ngx_msec_t later = 1005 + BRIX_SESSION_REAP_MIN_AGE_MS;

        CHECK(brix_session_scan(tbl, sessid, later, src_key, &sc) == 0,
              "still a miss at the later clock");
        CHECK(brix_session_reap_lru(tbl, later, sc.lru_slot, sc.lru_seen,
                                    &free_slot, victim) == 1,
              "reap succeeds once the LRU victim is aged");
        CHECK(free_slot == sc.lru_slot, "the reaped slot is the freed slot");
        CHECK(live_count(tbl) == 3, "reap evicted exactly one session");
        /* registry.c refills this slot immediately, which is why reap does not
         * itself shrink; the invariant must hold either way. */
        CHECK(prefix_covers_every_live_slot(tbl),
              "invariant holds after a reap, before the refill");
    }

    free(tbl);
}

/* ---- 3. security-negative: the prefix must not hide a slot -------------- */

/* An identity at its per-source cap must still self-evict its OWN LRU slot.
 * If the bounded scan could miss any of its slots, src_count would come in
 * under the cap and the quota would silently stop biting. */
static void
test_secneg_quota_sees_every_slot(void)
{
    brix_session_table_t *tbl = mktable(BRIX_SESSION_PER_SOURCE_SOFT_CAP * 4);
    brix_session_scan_t   sc;
    u_char                sessid[BRIX_SESSION_ID_LEN];
    u_char                victim[BRIX_SESSION_ID_LEN];
    ngx_uint_t            i, free_slot;
    char                  src_key[BRIX_SESSION_SRC_KEY_LEN];

    /* Interleave the greedy identity with innocent third parties, so its slots
     * are scattered across the prefix rather than packed at the front. */
    for (i = 0; i < BRIX_SESSION_PER_SOURCE_SOFT_CAP; i++) {
        (void) reg(tbl, 1000 + i, "greedy", 1000 + i);
        (void) reg(tbl, 5000 + i, "innocent", 1000 + i);
    }

    brix_session_src_key("greedy", 0, src_key);
    mksess(sessid, 9999);
    CHECK(brix_session_scan(tbl, sessid, 9000, src_key, &sc) == 0,
          "new session for the greedy identity misses");
    CHECK(sc.src_count == BRIX_SESSION_PER_SOURCE_SOFT_CAP,
          "the bounded scan counted EVERY one of the identity's slots");
    CHECK(sc.src_count >= BRIX_SESSION_PER_SOURCE_SOFT_CAP,
          "the per-source cap still bites");
    CHECK(sc.src_lru_slot == 0,
          "the identity's OWN least-recently-seen slot is nominated");

    CHECK(brix_session_src_cap_evict(tbl, sc.src_lru_slot, &free_slot,
                                     victim) == 1,
          "the over-quota identity self-evicts");
    CHECK(free_slot == 0, "self-eviction freed its own LRU slot");
    CHECK(victim[0] == (u_char) (1000 & 0xff)
          && victim[1] == (u_char) ((1000 >> 8) & 0xff),
          "the victim is the identity's OWN oldest session, not a third party's");
    CHECK(prefix_covers_every_live_slot(tbl),
          "invariant holds after self-eviction");

    /* The innocent identity lost nothing. */
    {
        ngx_uint_t innocent = 0;

        for (i = 0; i < tbl->capacity; i++) {
            if (tbl->slots[i].in_use
                && strcmp(tbl->slots[i].src_key, "d:innocent") == 0)
            {
                innocent++;
            }
        }
        CHECK(innocent == BRIX_SESSION_PER_SOURCE_SOFT_CAP,
              "no third-party slot was touched by the quota eviction");
    }

    free(tbl);
}

/* Churn the table through a long adversarial sequence of registrations and
 * disconnects — including holes, refills and frontier retreats — and assert
 * after EVERY step that no live slot ever sits beyond the prefix.  This is the
 * property that makes every bounded walk in the module safe. */
static void
test_secneg_invariant_under_churn(void)
{
    brix_session_table_t *tbl = mktable(64);
    unsigned              step, n;
    int                   ok = 1;
    const char           *who[3] = { "alice", "bob", "carol" };

    for (step = 0; step < 4000; step++) {
        n = step % 90;                       /* deliberately exceeds capacity */
        if ((step % 3) == 0) {
            (void) unreg(tbl, n);
        } else {
            (void) reg(tbl, n, who[step % 3], 1000 + step);
        }
        if (!prefix_covers_every_live_slot(tbl)) {
            ok = 0;
            break;
        }
        if (tbl->high_water > tbl->capacity) {
            ok = 0;
            break;
        }
    }
    CHECK(ok, "no live slot ever sits beyond the prefix, across 4000 churn steps");

    /* Draining every session must return the table to a zero-cost scan. */
    for (n = 0; n < 90; n++) {
        (void) unreg(tbl, n);
    }
    CHECK(live_count(tbl) == 0, "churn drained to empty");
    CHECK(tbl->high_water == 0,
          "a fully drained table retires its prefix (no permanent tax from a "
          "transient peak)");

    free(tbl);
}

int
main(void)
{
    test_success_prefix_tracking();
    test_boundary_holes_and_full();
    test_secneg_quota_sees_every_slot();
    test_secneg_invariant_under_churn();

    fprintf(stderr, "session_registry_high_water: %d passed, %d failed\n",
            g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
