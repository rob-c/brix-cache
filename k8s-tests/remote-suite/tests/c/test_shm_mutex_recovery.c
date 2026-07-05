/*
 * test_shm_mutex_recovery.c — regression: a module SHM-table mutex MUST be
 * recovered when the worker holding it dies, the same way nginx recovers the
 * slab pool's own mutex.
 *
 * THE BUG (workers stuck after many reboots)
 *   brix_shm_table_alloc() bound the table mutex to a lock word embedded in
 *   the slab-allocated table.  nginx's ngx_unlock_mutexes() — run on EVERY
 *   worker death — force-unlocks only &((ngx_slab_pool_t *)shm.addr)->mutex; it
 *   has no knowledge of a mutex embedded elsewhere in the zone.  So a worker
 *   SIGKILLed mid-critical-section (e.g. at reload's worker_shutdown_timeout)
 *   while holding the table mutex stranded it forever.  With the spin+yield
 *   lock (no timeout), every later kXR_open froze its whole worker, stalling
 *   all pinned connections.  The coincidence is rare per restart but becomes a
 *   near-certainty across MANY reload/restart cycles, and the stale lock
 *   survives reload via the persisted slab pool.
 *
 * THE FIX
 *   Bind the table mutex to the slab pool's OWN lock word (&sp->lock) — the
 *   exact word nginx force-unlocks for this zone on every worker death — so
 *   dead-holder recovery is inherited for free.
 *
 * THIS TEST
 *   Reproduces nginx's reaper primitive deterministically: acquire the table
 *   mutex as a fake worker PID, then run nginx's own recovery call
 *   ngx_shmtx_force_unlock(&sp->mutex, pid) and assert the table mutex is now
 *   free (a fresh worker can acquire it).  Pre-fix the mutex lives on a separate
 *   lock word that force-unlock never touches, so it stays held — FAIL.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include "core/compat/shm_slots.h"

#include <stdio.h>
#include <stdlib.h>

/* --- minimal nginx globals referenced by linked ngx_shmtx.o / shm_slots.o --- */
volatile ngx_cycle_t  *ngx_cycle;
ngx_pid_t              ngx_pid;
ngx_int_t              ngx_ncpu = 1;
ngx_uint_t             ngx_pagesize = 4096;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
                   const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

void
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
                   const char *fmt, ...)
{
    (void) level; (void) cf; (void) err; (void) fmt;
}

/* The fresh-alloc path calls this; this test drives only the reload (data)
 * path, so a call here signals the test built the wrong scenario. */
void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    (void) pool; (void) size;
    fprintf(stderr, "unexpected ngx_slab_alloc() — test drove the fresh path\n");
    abort();
}

/* A stand-in "previous cycle" table for the reload path. Its first member is an
 * ngx_shmtx_sh_t lock, matching the pre-fix table contract, so the OLD binding
 * would place the mutex here (and thus miss nginx's force-unlock). */
typedef struct {
    ngx_shmtx_sh_t  lock;
    ngx_uint_t      slots[16];
} fake_table_t;

int
main(void)
{
    static u_char zonebuf[64 * 1024] __attribute__((aligned(16)));
    static fake_table_t oldtbl;
    ngx_shm_zone_t  zone;
    ngx_shmtx_t     tbl_mtx;
    ngx_flag_t      fresh;
    ngx_slab_pool_t *sp;
    void            *tbl;
    ngx_pid_t        worker = 9999;

    ngx_cycle = NULL;                 /* success paths never dereference it */
    ngx_pid   = 4242;

    ngx_memzero(zonebuf, sizeof(zonebuf));
    ngx_memzero(&oldtbl, sizeof(oldtbl));
    ngx_memzero(&zone, sizeof(zone));
    ngx_memzero(&tbl_mtx, sizeof(tbl_mtx));

    /* Lay out the slab-pool header and create its own mutex over &sp->lock,
     * exactly as nginx's ngx_init_zone_pool() does before our init callback. */
    sp = (ngx_slab_pool_t *) zonebuf;
    if (ngx_shmtx_create(&sp->mutex, &sp->lock, NULL) != NGX_OK) {
        fprintf(stderr, "ngx_shmtx_create(sp->mutex) failed\n");
        return 2;
    }

    zone.shm.addr   = zonebuf;
    zone.shm.exists = 0;

    /* Reload path: nginx hands us the previous cycle's table via `data`. */
    tbl = brix_shm_table_alloc(&zone, &oldtbl, sizeof(oldtbl),
                                 &tbl_mtx, &fresh);
    if (tbl != &oldtbl) {
        fprintf(stderr, "brix_shm_table_alloc did not return the reload table\n");
        return 2;
    }

    /* A worker acquires the table mutex, then is SIGKILLed while holding it. */
    ngx_pid = worker;
    ngx_shmtx_lock(&tbl_mtx);

    /* nginx reaps the dead worker: ngx_unlock_mutexes() force-unlocks the
     * zone's slab-pool mutex. This is the ONLY recovery nginx performs. */
    ngx_shmtx_force_unlock(&sp->mutex, worker);

    /* A fresh worker tries to take the table mutex. It must succeed. */
    ngx_pid = 1234;
    if (!ngx_shmtx_trylock(&tbl_mtx)) {
        fprintf(stderr,
            "FAIL: table mutex still held by dead worker %ld after nginx "
            "force-unlocked the zone's slab mutex.\n"
            "      The table mutex is bound to a separate lock word that "
            "nginx never recovers, so every later kXR_open would spin forever "
            "(worker stuck after reboots).\n",
            (long) worker);
        return 1;
    }

    printf("PASS: a dead worker's table mutex is recovered by nginx's "
           "per-zone force-unlock (mutex shares &sp->lock)\n");
    return 0;
}
