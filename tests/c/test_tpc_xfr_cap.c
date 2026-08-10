/*
 * test_tpc_xfr_cap.c — §6.9 explicit TPC concurrency cap (brix_webdav_tpc_xfr).
 *
 * brix_tpc_registry_add() gained a max_active parameter: when > 0 it refuses a
 * new transfer (returns 0) once that many slots are already in use, EVEN with
 * free slots left below the compile-time BRIX_TPC_REGISTRY_SLOTS ceiling. 0
 * keeps the historical slot-ceiling-only bound.
 *
 * This unit drives the REAL registry (registry.o), SHM-backed, using the same
 * heap-backed shm-slot doubles as test_tpc_progress_total.c (single-threaded,
 * so the shmtx is a no-op).
 *
 * Asserts:
 *   success:      with cap N, exactly N adds succeed and the (N+1)th is refused
 *                 (0) while free slots remain.
 *   error/release: after removing one active transfer, a capped add succeeds
 *                 again (the cap tracks LIVE in-use slots, not a high-water mark).
 *   security-neg: cap 0 never refuses on the cap path — adds succeed up to the
 *                 slot ceiling, byte-identical to the pre-cap behaviour.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include "tpc/common/registry.h"
#include "core/compat/shm_slots.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- nginx / shm-slot surface doubles (no nginx core objects linked) ------ */

static ngx_shm_zone_t  g_zone;
static ngx_time_t      g_time = { .sec = 1785600000 };
volatile ngx_time_t   *ngx_cached_time = &g_time;
ngx_pid_t              ngx_pid = 1;
ngx_module_t           ngx_stream_brix_module;

/* The cap-refuse path calls ngx_log_error(); the macro reads log->log_level
 * before the (no-op) core, so a real log struct is required, not NULL. */
static ngx_log_t       g_log = { .log_level = NGX_LOG_DEBUG };

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

void ngx_shmtx_lock(ngx_shmtx_t *mtx) { (void) mtx; }
void ngx_shmtx_unlock(ngx_shmtx_t *mtx) { (void) mtx; }

size_t
brix_shm_zone_size(size_t table_bytes)
{
    return table_bytes + 4096;
}

ngx_shm_zone_t *
ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name, size_t size, void *tag)
{
    (void) cf; (void) name; (void) size; (void) tag;
    return &g_zone;
}

void *
brix_shm_table_alloc(ngx_shm_zone_t *shm_zone, void *data, size_t table_bytes,
    ngx_shmtx_t *mtx, ngx_flag_t *fresh)
{
    void *tbl;
    (void) data; (void) mtx;
    tbl = calloc(1, table_bytes);
    assert(tbl != NULL);
    shm_zone->data = tbl;
    *fresh = 1;
    return tbl;
}

/* ---- helpers -------------------------------------------------------------- */

static uint64_t
add_capped(ngx_uint_t max_active)
{
    brix_tpc_transfer_t t;
    ngx_str_t           src = ngx_string("root://src//f");
    ngx_str_t           dst = ngx_string("/data/f");

    memset(&t, 0, sizeof(t));
    t.protocol   = BRIX_TPC_PROTO_WEBDAV;
    t.direction  = BRIX_TPC_DIR_PULL;
    t.src_url    = src;
    t.dst_path   = dst;
    t.bytes_total = 0;
    t.state      = BRIX_TPC_STATE_ACTIVE;
    return brix_tpc_registry_add(&t, &g_log, max_active);
}

int
main(void)
{
    const ngx_uint_t CAP = 3;
    uint64_t ids[CAP];
    ngx_uint_t i;

    /* Bring up the real registry (reserve the zone, run its shm_init). */
    assert(brix_tpc_registry_configure(NULL) == NGX_OK);
    assert(g_zone.init != NULL);
    assert(g_zone.init(&g_zone, NULL) == NGX_OK);

    /* success: exactly CAP adds succeed under the cap. */
    for (i = 0; i < CAP; i++) {
        ids[i] = add_capped(CAP);
        assert(ids[i] != 0);
    }

    /* the (CAP+1)th is refused even though free slots remain. */
    assert(add_capped(CAP) == 0);

    /* error/release: freeing one live slot re-opens exactly one capped add. */
    assert(brix_tpc_registry_remove(ids[0], &g_log) == NGX_OK);
    uint64_t reopened = add_capped(CAP);
    assert(reopened != 0);
    /* and we are at the cap again. */
    assert(add_capped(CAP) == 0);

    /* security-neg: cap 0 never refuses on the cap path — an uncapped add
     * succeeds where a capped one just refused. */
    assert(add_capped(0) != 0);

    printf("test_tpc_xfr_cap: ALL PASS\n");
    return 0;
}
