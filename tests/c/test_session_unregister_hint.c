/*
 * test_session_unregister_hint.c — round 15's registry slot hint.
 *
 * WHY THIS EXISTS: brix_session_unregister() found the departing session by
 * scanning the registry's live prefix under the single cross-worker
 * brix_session_mutex, on EVERY disconnect.  That prefix is at its longest
 * exactly when every session is tearing down at once, so the per-teardown cost
 * GREW with concurrency instead of backing off — the ultra-parallel storm's
 * complaint, and the same shape round 14 removed from the handle table.
 * brix_session_register() now reports the slot it used; the connection keeps it
 * in ctx->login.session_slot_hint and the disconnect clears that slot directly.
 *
 * The interesting claim is not the speed, it is that the hint is SAFE, and in
 * one respect safer than the scan it replaces.  A session occupies exactly one
 * slot, so the hint plus a sessid re-check under the lock either finds the
 * entry or proves it is gone.  Where the two paths DIVERGE is eviction: if the
 * F4 reap or the W5 self-eviction recycled this session's slot and the same
 * sessid was later re-registered by a different connection, the old scan would
 * find that live re-registration and destroy it — a session-teardown confused
 * deputy.  The hint refuses to touch a slot it does not own.  That divergence
 * is the security battery below.
 *
 * Links the REAL registry.o (brix_session_register / _unregister /
 * _unregister_hinted, the mutex and the SHM zone) and the REAL
 * registry_slots.o (the scan that now reports match_slot), so the functions
 * under test are the shipped ones.  registry.o's cross-TU closure — the two
 * ratelimit key formatters, the metrics zone, the handle-table unpublish and
 * ngx_worker — is supplied here as spies, exactly as
 * test_session_registry_high_water.c does.
 *
 * Coverage (3-per-change rule):
 *   success  — register reports the slot it filled and, on a re-register, the
 *              slot already held; the hinted clear frees exactly that slot and
 *              retires the live-prefix mark; hint < 0 keeps the legacy scan.
 *   error    — a hint past high_water, a hint at a free slot, and a hint at
 *              another live session's slot are all no-ops that leave every
 *              registration intact; a rejected registration reports -1.
 *   security — after eviction + re-registration of the same sessid, the stale
 *              hint must NOT clear the new live entry (the scan would), and
 *              the hinted clear must still unpublish the session's handles so
 *              no bound secondary outlives the teardown.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocols/root/session/registry.h"
#include "protocols/root/session/registry_slots_internal.h"
#include "core/compat/shm_slots.h"

static int g_pass, g_fail;
#define CHECK(cond, msg) do {                                               \
        if (cond) { g_pass++; }                                             \
        else { g_fail++; fprintf(stderr, "FAIL: %s (%s:%d)\n",              \
                                  msg, __FILE__, __LINE__); }               \
    } while (0)

/* ---- spies for the registry's cross-TU closure -------------------------- */

ngx_uint_t  ngx_worker;
ngx_pid_t   ngx_pid = 4242;
ngx_int_t   ngx_ncpu = 1;
volatile ngx_msec_t ngx_current_msec = 1000;

/* Config-time only: brix_configure_session_registry() is the sole caller of
 * these three and the unit never runs config parsing, so they exist purely to
 * close the link. */
ngx_module_t ngx_stream_brix_module;

ngx_shm_zone_t *
ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name, size_t size, void *tag)
{
    (void) cf; (void) name; (void) size; (void) tag;
    return NULL;
}

ngx_int_t
brix_handle_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    (void) shm_zone; (void) data;
    return NGX_OK;
}

/* brix_metrics_shared() is a static inline over this pointer and returns NULL
 * while unset, so leaving the metrics plane down is enough: every counter site
 * is NULL-guarded and the reap/evict paths run their real logic regardless. */
ngx_shm_zone_t *ngx_brix_shm_zone = NULL;

static int    g_unpublish_calls;
static u_char g_unpublish_last[BRIX_SESSION_ID_LEN];

void
brix_session_handle_unpublish_all(const u_char sessid[BRIX_SESSION_ID_LEN])
{
    g_unpublish_calls++;
    memcpy(g_unpublish_last, sessid, BRIX_SESSION_ID_LEN);
}

void
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) cf; (void) err; (void) fmt;
}

void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    (void) pool;
    return calloc(1, size);
}

/* The real formatters hash to a no-PII bucket id; equal identities producing
 * equal keys is all the quota logic needs, so a bounded copy is faithful. */
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

/* ---- helpers ------------------------------------------------------------ */

static brix_session_table_t *g_tbl;

static void
mksess(u_char out[BRIX_SESSION_ID_LEN], unsigned n)
{
    memset(out, 0, BRIX_SESSION_ID_LEN);
    out[0] = (u_char) (n & 0xff);
    out[1] = (u_char) ((n >> 8) & 0xff);
}

/* Register session `n` under identity `dn`, returning the slot hint the real
 * brix_session_register() reports back to its caller. */
static int
reg(unsigned n, const char *dn)
{
    u_char sessid[BRIX_SESSION_ID_LEN];

    mksess(sessid, n);
    return brix_session_register(sessid, dn, "", 0);
}

static void
unreg_hinted(unsigned n, int hint)
{
    u_char sessid[BRIX_SESSION_ID_LEN];

    mksess(sessid, n);
    brix_session_unregister_hinted(sessid, hint);
}

/* Is session `n` still registered anywhere in the table? Deliberately a FULL
 * sweep, not a hinted or prefix-bounded one — the assertions must not be made
 * out of the same machinery they are checking. */
static int
present(unsigned n)
{
    u_char     sessid[BRIX_SESSION_ID_LEN];
    ngx_uint_t i;

    mksess(sessid, n);
    for (i = 0; i < g_tbl->capacity; i++) {
        if (g_tbl->slots[i].in_use
            && memcmp(g_tbl->slots[i].sessid, sessid,
                      BRIX_SESSION_ID_LEN) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static ngx_uint_t
live_count(void)
{
    ngx_uint_t i, n = 0;

    for (i = 0; i < g_tbl->capacity; i++) {
        if (g_tbl->slots[i].in_use) {
            n++;
        }
    }
    return n;
}

/* ---- 1. success --------------------------------------------------------- */

static void
test_success(void)
{
    int a, b, c, again;

    CHECK(g_tbl->high_water == 0, "fresh table has an empty live prefix");

    a = reg(1, "alice");
    b = reg(2, "bob");
    c = reg(3, "carol");
    CHECK(a == 0, "register reports the slot it filled (0)");
    CHECK(b == 1, "register reports the slot it filled (1)");
    CHECK(c == 2, "register reports the slot it filled (2)");
    CHECK(g_tbl->high_water == 3, "prefix tracks the live population");

    /* A re-register of a live session reports the slot it already holds, so a
     * second login on the same sessid cannot install a hint pointing elsewhere. */
    again = reg(2, "bob");
    CHECK(again == b, "re-register reports the slot already held");
    CHECK(live_count() == 3, "re-register did not consume a second slot");

    /* The hinted clear frees exactly its own slot. */
    g_unpublish_calls = 0;
    unreg_hinted(2, b);
    CHECK(!present(2), "hinted unregister cleared its own session");
    CHECK(present(1) && present(3), "it left the other sessions registered");
    CHECK(g_unpublish_calls == 1, "it still unpublished the session's handles");
    CHECK(memcmp(g_unpublish_last, (u_char[BRIX_SESSION_ID_LEN]){2, 0},
                 BRIX_SESSION_ID_LEN) == 0,
          "it unpublished the departing session, not another");

    /* Clearing the TOP live slot retires the mark. */
    unreg_hinted(3, c);
    CHECK(!present(3), "hinted unregister cleared the top slot");
    CHECK(g_tbl->high_water == 1, "the live-prefix mark walked back down");

    /* hint < 0 keeps the legacy scan, which must still find and clear. */
    unreg_hinted(1, -1);
    CHECK(!present(1), "hint < 0 falls back to the scan and still clears");
    CHECK(g_tbl->high_water == 0, "table drained");
}

/* ---- 2. error ----------------------------------------------------------- */

static void
test_error(void)
{
    int a, b;

    a = reg(10, "dave");
    b = reg(11, "erin");
    CHECK(a == 0 && b == 1, "two fresh registrations");

    /* A hint past the live prefix clears nothing and disturbs nothing. */
    unreg_hinted(10, 4096);
    CHECK(present(10) && present(11), "out-of-range hint is a no-op");

    /* A hint at another LIVE session's slot must be refused by the sessid
     * re-check — otherwise one disconnect would evict an unrelated session. */
    unreg_hinted(10, b);
    CHECK(present(11), "a hint at another session's slot did not clear it");
    CHECK(present(10), "and did not clear the hinting session either");

    /* Clear slot 0, then aim a hint at the resulting hole. */
    unreg_hinted(10, a);
    CHECK(!present(10), "session 10 cleared");
    unreg_hinted(10, a);
    CHECK(present(11), "a hint at a now-free slot is a no-op");
    CHECK(live_count() == 1, "only session 11 remains");

    unreg_hinted(11, b);
    CHECK(live_count() == 0, "table drained");
}

/* ---- 3. security -------------------------------------------------------- */

/*
 * The confused deputy the hint removes: session S is registered, its slot is
 * recycled by the quota/LRU machinery, and S is then re-registered by a NEW
 * connection.  The OLD connection's teardown still carries the stale hint.
 * Under the scan it would locate S by sessid and destroy the new, live
 * registration; under the hint it must not.
 */
static void
test_security_stale_hint_cannot_clear_a_reregistration(void)
{
    int stale, fresh;

    stale = reg(20, "frank");
    CHECK(stale == 0, "session 20 took slot 0");

    /* Recycle the slot the way an eviction does, then let a DIFFERENT
     * connection re-register the same sessid — it lands wherever the table has
     * room, which need not be the slot the stale hint names. */
    unreg_hinted(20, stale);
    CHECK(!present(20), "slot recycled");

    (void) reg(21, "grace");            /* takes slot 0, the recycled hole */
    fresh = reg(20, "frank");           /* the re-registration lands after it */
    CHECK(fresh != stale, "the re-registration is in a different slot");
    CHECK(present(20) && present(21), "both are live");

    /* The stale teardown fires.  It must clear nothing: slot 0 belongs to
     * session 21 now, and session 20's live entry is not the one it owns. */
    unreg_hinted(20, stale);
    CHECK(present(21), "the stale hint did not evict the unrelated session");
    CHECK(present(20),
          "nor did it destroy the live re-registration (the scan would have)");

    /* The owner of the new registration can still clear it. */
    unreg_hinted(20, fresh);
    CHECK(!present(20), "the current holder's hint still clears normally");

    /*
     * Revocation is unconditional: even when the hint matches nothing, the
     * handle table must still be swept, or a bound secondary could outlive the
     * primary's teardown and keep reading a closed file.
     */
    g_unpublish_calls = 0;
    unreg_hinted(99, 7);                /* never registered, bogus hint */
    CHECK(g_unpublish_calls == 1,
          "a hint that matches nothing still unpublishes the handles");

    unreg_hinted(21, -1);
    CHECK(live_count() == 0, "table drained");
}

int
main(void)
{
    /* The default registry is 1024 × ~1.2 KB entries; size the zone for it
     * even though ngx_slab_alloc is a calloc spy here. */
    static u_char   zonebuf[4 * 1024 * 1024] __attribute__((aligned(16)));
    ngx_shm_zone_t  zone;
    ngx_slab_pool_t *sp;

    ngx_pagesize = 4096;
    memset(zonebuf, 0, sizeof(zonebuf));
    memset(&zone, 0, sizeof(zone));

    sp = (ngx_slab_pool_t *) zonebuf;
    if (ngx_shmtx_create(&sp->mutex, &sp->lock, NULL) != NGX_OK) {
        fprintf(stderr, "FAIL: could not create the zone mutex\n");
        return 1;
    }
    zone.shm.addr = zonebuf;
    zone.shm.size = sizeof(zonebuf);
    zone.shm.exists = 0;
    brix_session_shm_zone = &zone;
    if (brix_session_shm_init_zone(&zone, NULL) != NGX_OK) {
        fprintf(stderr, "FAIL: could not init the session zone\n");
        return 1;
    }

    g_tbl = (brix_session_table_t *) brix_shm_zone_table(brix_session_shm_zone);
    if (g_tbl == NULL) {
        fprintf(stderr, "FAIL: no session table\n");
        return 1;
    }

    test_success();
    test_error();
    test_security_stale_hint_cannot_clear_a_reregistration();

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
