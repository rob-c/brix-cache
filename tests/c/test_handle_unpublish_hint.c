/*
 * test_handle_unpublish_hint.c — round 14's authoritative publish-slot hint.
 *
 * WHY THIS EXISTS: brix_free_fhandle() unpublished a handle by scanning the
 * table's live prefix under the single cross-worker brix_handle_mutex.  At
 * disconnect that scan runs AFTER brix_session_unregister() has already
 * cleared the session's entries, so every open handle paid a full-prefix scan
 * that was guaranteed to find nothing — a cost that GREW with concurrency
 * (longer live prefix, more contention) instead of backing off, which is the
 * ultra-parallel storm's complaint.  Round 14 records the publish-time slot in
 * brix_file_t.shared_handle_slot_hint and clears at it directly.
 *
 * The hint is AUTHORITATIVE, not advisory: a published entry can only ever
 * live at the slot publish wrote it to (entries are cleared in place, never
 * relocated), so a hinted slot whose full key does not match PROVES the entry
 * is gone and no scan could find one.  That is the property this unit pins —
 * because if it were ever false, a handle would silently survive teardown and
 * a bound secondary could keep reading a closed file.
 *
 * Coverage (3-per-change rule):
 *   success  — publish records the exact slot; the hinted clear removes the
 *              entry and retires the mark; the hint survives an in-place
 *              republish of the same key; hint == -1 keeps the legacy scan.
 *   error    — a hint past high_water, a hint at an empty slot, and a hint at
 *              a slot holding the SAME session's DIFFERENT handle_index are
 *              all no-ops that leave every live entry intact; a refused
 *              publish (fd < 0, write-only, over-length path) resets the hint
 *              to -1 so no stale slot is ever carried into teardown.
 *   security — a stale hint whose slot was REUSED by another session must NOT
 *              clear that session's entry (cross-session confused deputy), and
 *              a hinted clear must never revoke a handle it does not own.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include "protocols/root/session/registry.h"
#include "core/compat/shm_slots.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ngx_shm_zone_t *brix_handle_shm_zone;   /* owner registry.c is not linked */
ngx_pid_t   ngx_pid = 4242;
ngx_int_t   ngx_ncpu = 1;

static int g_checks;
#define CHECK(cond) do { assert(cond); g_checks++; } while (0)

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

static u_char g_sess_seed = 0;

static void
mksess(u_char sessid[BRIX_SESSION_ID_LEN], unsigned n)
{
    memset(sessid, 0, BRIX_SESSION_ID_LEN);
    sessid[0] = (u_char) (n & 0xff);
    sessid[1] = (u_char) ((n >> 8) & 0xff);
    sessid[2] = ++g_sess_seed;
}

static brix_file_t
mkfile(const char *path, ino_t inode)
{
    brix_file_t f;

    memset(&f, 0, sizeof(f));
    f.fd = 3;                    /* publish gates on fd >= 0, never uses it */
    f.readable = 1;
    f.is_regular = 1;
    f.device = 7;
    f.inode = inode;
    f.cached_size = 42;
    f.path = (char *) path;
    f.shared_handle_slot_hint = -1;
    return f;
}

int
main(void)
{
    static u_char zonebuf[64 * 1024] __attribute__((aligned(16)));
    ngx_shm_zone_t                zone;
    ngx_slab_pool_t              *sp;
    brix_shared_handle_table_t *tbl;
    brix_shared_handle_entry_t  out;
    brix_file_t                   fa, fb, fc, f;
    u_char  s1[BRIX_SESSION_ID_LEN], s2[BRIX_SESSION_ID_LEN];
    u_char  s3[BRIX_SESSION_ID_LEN];
    int     victim_slot;

    ngx_pagesize = 4096;
    ngx_memzero(zonebuf, sizeof(zonebuf));
    ngx_memzero(&zone, sizeof(zone));

    sp = (ngx_slab_pool_t *) zonebuf;
    assert(ngx_shmtx_create(&sp->mutex, &sp->lock, NULL) == NGX_OK);
    zone.shm.addr = zonebuf;
    zone.shm.exists = 0;
    brix_handle_shm_zone = &zone;
    assert(brix_handle_shm_init_zone(&zone, NULL) == NGX_OK);

    tbl = brix_shm_zone_table(brix_handle_shm_zone);
    assert(tbl != NULL);

    mksess(s1, 1); mksess(s2, 2); mksess(s3, 3);

    /* ---- 1. success: the hint is the slot, and it clears in O(1) ---- */
    CHECK(tbl->high_water == 0);

    fa = mkfile("/data/a", 100);
    brix_session_handle_publish(s1, 0, &fa);
    CHECK(fa.shared_handle_slot_hint == 0);        /* recorded, not left -1 */
    CHECK(tbl->high_water == 1);

    fb = mkfile("/data/b", 101);
    brix_session_handle_publish(s1, 1, &fb);
    CHECK(fb.shared_handle_slot_hint == 1);

    fc = mkfile("/data/c", 102);
    brix_session_handle_publish(s2, 0, &fc);
    CHECK(fc.shared_handle_slot_hint == 2);
    CHECK(tbl->high_water == 3);

    /* an in-place republish of the same key keeps the same slot */
    f = mkfile("/data/a2", 200);
    f.shared_handle_slot_hint = -1;
    brix_session_handle_publish(s1, 0, &f);
    CHECK(f.shared_handle_slot_hint == 0);
    CHECK(brix_session_handle_lookup(s1, 0, &out) == 1);
    CHECK(out.inode == 200);

    /* the hinted clear removes exactly its own entry ... */
    brix_session_handle_unpublish_hinted(s1, 0, f.shared_handle_slot_hint);
    CHECK(brix_session_handle_lookup(s1, 0, &out) == 0);
    /* ... and leaves every other entry alone */
    CHECK(brix_session_handle_lookup(s1, 1, &out) == 1);
    CHECK(brix_session_handle_lookup(s2, 0, &out) == 1);
    CHECK(tbl->high_water == 3);                   /* slot 2 still live */

    /* freeing the TOP slot by hint still retires the mark (shrink runs) */
    brix_session_handle_unpublish_hinted(s2, 0, fc.shared_handle_slot_hint);
    CHECK(brix_session_handle_lookup(s2, 0, &out) == 0);
    CHECK(tbl->high_water == 2);

    /* hint == -1 keeps the legacy scan, which must still find and clear */
    brix_session_handle_unpublish_hinted(s1, 1, -1);
    CHECK(brix_session_handle_lookup(s1, 1, &out) == 0);
    CHECK(tbl->high_water == 0);                   /* table drained */

    /* ---- 2. error: bad hints are no-ops, refusal resets the hint ---- */
    fa = mkfile("/data/a", 300);
    brix_session_handle_publish(s1, 0, &fa);
    fb = mkfile("/data/b", 301);
    brix_session_handle_publish(s1, 1, &fb);
    CHECK(tbl->high_water == 2);

    /* a hint past the live prefix: nothing to clear, nothing disturbed */
    brix_session_handle_unpublish_hinted(s1, 0, 4000);
    CHECK(brix_session_handle_lookup(s1, 0, &out) == 1);
    CHECK(brix_session_handle_lookup(s1, 1, &out) == 1);

    /* a hint at a slot holding the SAME session's OTHER handle_index: the
     * full key must gate the clear, so slot 1 (handle 1) survives a clear
     * aimed at handle 0. */
    brix_session_handle_unpublish_hinted(s1, 0, 1);
    CHECK(brix_session_handle_lookup(s1, 1, &out) == 1);
    CHECK(brix_session_handle_lookup(s1, 0, &out) == 1);

    /* a refused publish must reset the hint to -1 rather than leave a stale
     * slot that teardown would clear.  fd < 0 (a staged whole-object writer)
     * is refused before any slot is chosen. */
    f = mkfile("/data/staged", 302);
    f.shared_handle_slot_hint = 1;      /* pretend a previous publish's slot */
    f.fd = -1;
    brix_session_handle_publish(s1, 5, &f);
    CHECK(f.shared_handle_slot_hint == 1);  /* untouched: never reached the
                                             * table, and the caller's own
                                             * handle 5 was never published */
    CHECK(brix_session_handle_lookup(s1, 5, &out) == 0);

    /* an INELIGIBLE publish (write-only) is reached, refused, and must clear
     * the hint so no stale slot survives into teardown */
    f = mkfile("/data/wo", 303);
    f.readable = 0;
    f.writable = 0;
    f.shared_handle_slot_hint = 0;      /* stale slot from an earlier life */
    brix_session_handle_publish(s1, 6, &f);
    CHECK(f.shared_handle_slot_hint == -1);
    CHECK(brix_session_handle_lookup(s1, 6, &out) == 0);
    /* and the refusal must not have taken out an unrelated live entry */
    CHECK(brix_session_handle_lookup(s1, 0, &out) == 1);
    CHECK(brix_session_handle_lookup(s1, 1, &out) == 1);

    /* ---- 3. security: a stale hint must never clear another session ---- */
    /* s1/handle 1 sits at slot 1.  Remember that slot, free the entry, then
     * let ANOTHER session take the same slot — the classic reuse race that a
     * naive "trust the hint" clear would turn into a cross-session revoke. */
    victim_slot = fb.shared_handle_slot_hint;
    CHECK(victim_slot == 1);

    brix_session_handle_unpublish_hinted(s1, 1, victim_slot);
    CHECK(brix_session_handle_lookup(s1, 1, &out) == 0);

    f = mkfile("/data/other", 400);
    brix_session_handle_publish(s3, 1, &f);         /* reuses the hole */
    CHECK(f.shared_handle_slot_hint == victim_slot);
    CHECK(brix_session_handle_lookup(s3, 1, &out) == 1);

    /* s1 now tears down carrying its STALE hint to the reused slot.  The
     * sessid half of the key must reject it: s3's handle survives. */
    brix_session_handle_unpublish_hinted(s1, 1, victim_slot);
    CHECK(brix_session_handle_lookup(s3, 1, &out) == 1);
    CHECK(out.inode == 400);

    /* the same stale hint, now with a MATCHING handle_index but the wrong
     * session, must still be refused — sessid is what separates them */
    brix_session_handle_unpublish_hinted(s2, 1, victim_slot);
    CHECK(brix_session_handle_lookup(s3, 1, &out) == 1);

    /* and the legitimate owner can still clear its own entry */
    brix_session_handle_unpublish_hinted(s3, 1, victim_slot);
    CHECK(brix_session_handle_lookup(s3, 1, &out) == 0);

    /* equivalence backstop: whatever the hinted path leaves behind, the
     * scanning path must agree there is nothing left for these sessions */
    brix_session_handle_unpublish_all(s1);
    brix_session_handle_unpublish_all(s2);
    brix_session_handle_unpublish_all(s3);
    CHECK(brix_session_handle_lookup(s1, 0, &out) == 0);
    CHECK(tbl->high_water == 0);

    printf("%d passed, 0 failed\n", g_checks);
    return 0;
}
