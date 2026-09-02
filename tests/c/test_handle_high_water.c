/*
 * test_handle_high_water.c — the shared handle table's high-water mark.
 *
 * WHY THIS EXISTS: every kXR_open published into a 4096-slot × ~4 KB shm
 * table by scanning ALL of it (~17 MB walked per open) — 25% of worker CPU
 * on open-heavy metadata workloads.  The fix bounds every scan (publish,
 * lookup, unpublish, unpublish_all) by a mutex-guarded `high_water` mark
 * that tracks the peak LIVE population and walks back down over a freed top
 * run.  This unit pins the mark's whole lifecycle against the REAL
 * handles.o + shm_slots.o + ngx_shmtx.o, reading tbl->high_water directly.
 *
 * Coverage (3-per-change rule):
 *   success  — growth, in-place republish, hole reuse below the mark, the
 *              frontier slot as free fallback, shrink on top-run free and on
 *              unpublish_all, restart from empty.
 *   error    — out-of-range handle_index, fd < 0 (staged writers are never
 *              published), and the FULL table: graceful refusal at 4096,
 *              then success into a freed hole.
 *   security — ineligibility (write-only / over-length path) must EVICT the
 *              stale entry, not leave it readable; a stale lookup hint whose
 *              slot was reused by ANOTHER session must revoke (return 0),
 *              never serve the other session's handle.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include "protocols/root/session/registry.h"
#include "core/compat/shm_slots.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- globals/stubs the linked nginx objects need (ngx_cycle and
 * ngx_log_error_core come from ngx_link_stubs.c) --- */
ngx_shm_zone_t *brix_handle_shm_zone;   /* owner registry.c is not linked */
ngx_pid_t   ngx_pid = 4242;
ngx_int_t   ngx_ncpu = 1;
/* ngx_pagesize is owned by the linked ngx_alloc.o; set at runtime in main */

void
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) cf; (void) err; (void) fmt;
}

/* Fresh-path table allocation: the real slab pool is irrelevant here, the
 * table just needs ~17 MB of zeroed memory. */
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
    sessid[2] = ++g_sess_seed;   /* never collides across mksess calls */
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
    brix_file_t                   f;
    u_char  s1[BRIX_SESSION_ID_LEN], s2[BRIX_SESSION_ID_LEN];
    u_char  s3[BRIX_SESSION_ID_LEN], s4[BRIX_SESSION_ID_LEN];
    u_char  sa[BRIX_SESSION_ID_LEN], sb[BRIX_SESSION_ID_LEN];
    int     hint;
    unsigned n, k;

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

    /* ---- 1. success: growth, in-place republish, hole reuse, shrink ---- */
    assert(tbl->high_water == 0);

    mksess(s1, 1); mksess(s2, 2); mksess(s3, 3); mksess(s4, 4);

    f = mkfile("/data/a", 100);
    brix_session_handle_publish(s1, 0, &f);          /* slot 0 */
    assert(tbl->high_water == 1);
    assert(brix_session_handle_lookup(s1, 0, &out) == 1);
    assert(out.inode == 100 && strcmp(out.path, "/data/a") == 0);

    f = mkfile("/data/b", 101);
    brix_session_handle_publish(s1, 1, &f);          /* slot 1 */
    f = mkfile("/data/c", 102);
    brix_session_handle_publish(s2, 0, &f);          /* slot 2 */
    assert(tbl->high_water == 3);

    /* republish the same key: in-place overwrite, no growth */
    f = mkfile("/data/a2", 200);
    brix_session_handle_publish(s1, 0, &f);
    assert(tbl->high_water == 3);
    assert(brix_session_handle_lookup(s1, 0, &out) == 1);
    assert(out.inode == 200 && strcmp(out.path, "/data/a2") == 0);

    /* free a MIDDLE slot: the mark must not move (slot 2 is still live) */
    brix_session_handle_unpublish(s1, 1);
    assert(tbl->high_water == 3);
    assert(brix_session_handle_lookup(s1, 1, &out) == 0);

    /* a new publish reuses the hole below the mark, not the frontier */
    f = mkfile("/data/d", 103);
    brix_session_handle_publish(s3, 0, &f);          /* slot 1 again */
    assert(tbl->high_water == 3);

    /* free the TOP slot: shrink walks the mark down over the freed run */
    brix_session_handle_unpublish(s2, 0);
    assert(tbl->high_water == 2);

    /* unpublish_all clears every entry of a session, then shrinks once */
    brix_session_handle_unpublish_all(s1);           /* clears slot 0 */
    assert(tbl->high_water == 2);                    /* slot 1 (s3) live */
    brix_session_handle_unpublish_all(s3);           /* clears slot 1 */
    assert(tbl->high_water == 0);

    /* restart from empty: the frontier fallback hands out slot 0 */
    f = mkfile("/data/e", 104);
    brix_session_handle_publish(s4, 0, &f);
    assert(tbl->high_water == 1);
    assert(brix_session_handle_lookup(s4, 0, &out) == 1);
    brix_session_handle_unpublish_all(s4);
    assert(tbl->high_water == 0);
    printf("1. growth/reuse/shrink lifecycle OK\n");

    /* ---- 2. error: bad index, fd < 0, and the full table ---- */
    f = mkfile("/data/x", 300);
    brix_session_handle_publish(s1, -1, &f);
    brix_session_handle_publish(s1, BRIX_MAX_FILES, &f);
    assert(tbl->high_water == 0);
    assert(brix_session_handle_lookup(s1, -1, &out) == 0);
    assert(brix_session_handle_lookup(s1, BRIX_MAX_FILES, &out) == 0);

    f = mkfile("/data/x", 301);
    f.fd = -1;                       /* staged whole-object writer */
    brix_session_handle_publish(s1, 0, &f);
    assert(tbl->high_water == 0);
    assert(brix_session_handle_lookup(s1, 0, &out) == 0);

    /* fill ALL 4096 slots (512 sessions x 8 handles) */
    for (n = 0; n < BRIX_SESSION_HANDLE_SESSIONS; n++) {
        u_char sid[BRIX_SESSION_ID_LEN];

        memset(sid, 0, sizeof(sid));
        sid[0] = (u_char) (n & 0xff);
        sid[1] = (u_char) (n >> 8);
        sid[2] = 0xee;               /* fixed marker, distinct from mksess */
        for (k = 0; k < BRIX_SESSION_HANDLES_PER_SESSION; k++) {
            f = mkfile("/bulk/f", 1000 + n * 8 + k);
            brix_session_handle_publish(sid, (int) k, &f);
        }
    }
    assert(tbl->high_water == BRIX_SESSION_HANDLE_SLOTS);

    /* one more publish must refuse gracefully — no eviction, no growth */
    f = mkfile("/data/overflow", 400);
    brix_session_handle_publish(s2, 5, &f);
    assert(brix_session_handle_lookup(s2, 5, &out) == 0);
    assert(tbl->high_water == BRIX_SESSION_HANDLE_SLOTS);

    /* free one middle entry; the refused publish now lands in the hole */
    {
        u_char sid[BRIX_SESSION_ID_LEN];

        memset(sid, 0, sizeof(sid));
        sid[0] = 200; sid[1] = 0; sid[2] = 0xee;
        brix_session_handle_unpublish(sid, 3);
    }
    brix_session_handle_publish(s2, 5, &f);
    assert(brix_session_handle_lookup(s2, 5, &out) == 1);
    assert(out.inode == 400);
    assert(tbl->high_water == BRIX_SESSION_HANDLE_SLOTS);

    /* drain everything; the mark must return exactly to zero */
    for (n = 0; n < BRIX_SESSION_HANDLE_SESSIONS; n++) {
        u_char sid[BRIX_SESSION_ID_LEN];

        memset(sid, 0, sizeof(sid));
        sid[0] = (u_char) (n & 0xff);
        sid[1] = (u_char) (n >> 8);
        sid[2] = 0xee;
        brix_session_handle_unpublish_all(sid);
    }
    brix_session_handle_unpublish_all(s2);
    assert(tbl->high_water == 0);
    printf("2. bounds/full-table refusal + hole landing OK\n");

    /* ---- 3. security: eviction on ineligibility; stale-hint revocation --- */
    mksess(sa, 10); mksess(sb, 11);

    /* 3a. a write-only republish must evict the readable entry (bound
     * streams must never keep serving a handle downgraded to write-only) */
    f = mkfile("/sec/a", 500);
    brix_session_handle_publish(sa, 0, &f);
    assert(tbl->high_water == 1);
    f = mkfile("/sec/a", 500);
    f.readable = 0;                  /* neither readable nor writable... */
    f.writable = 0;                  /* ...=> ineligible, must evict */
    brix_session_handle_publish(sa, 0, &f);
    assert(brix_session_handle_lookup(sa, 0, &out) == 0);
    assert(tbl->high_water == 0);    /* eviction also shrinks the mark */

    /* 3b. an over-length path must evict, never publish truncated */
    {
        static char longpath[BRIX_MAX_PATH + 8];

        memset(longpath, 'p', sizeof(longpath) - 1);
        longpath[0] = '/';
        longpath[sizeof(longpath) - 1] = '\0';

        f = mkfile("/sec/b", 501);
        brix_session_handle_publish(sa, 1, &f);
        assert(brix_session_handle_lookup(sa, 1, &out) == 1);
        f = mkfile(longpath, 501);
        brix_session_handle_publish(sa, 1, &f);
        assert(brix_session_handle_lookup(sa, 1, &out) == 0);
        assert(tbl->high_water == 0);
    }

    /* 3c. stale hint whose slot was REUSED by another session: the fast
     * path re-checks the full key, so lookup must revoke, never serve the
     * other session's handle */
    f = mkfile("/sec/mine", 600);
    brix_session_handle_publish(sa, 3, &f);
    hint = -1;
    assert(brix_session_handle_lookup_hint(sa, 3, &hint, &out) == 1);
    assert(hint == 0);               /* slot 0 cached for the next read */
    brix_session_handle_unpublish(sa, 3);
    f = mkfile("/sec/theirs", 601);
    brix_session_handle_publish(sb, 3, &f);   /* same slot, same index */
    assert(brix_session_handle_lookup_hint(sa, 3, &hint, &out) == 0);
    assert(hint == -1);              /* stale hint dropped, not refreshed */
    assert(brix_session_handle_lookup_hint(sb, 3, &hint, &out) == 1);
    assert(out.inode == 601);
    printf("3. eviction + stale-hint revocation OK\n");

    printf("PASS: handle-table high-water mark lifecycle\n");
    return 0;
}
