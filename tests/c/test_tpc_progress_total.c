/*
 * test_tpc_progress_total.c — O-2: the TPC dashboard bytes_total is threaded
 * through the progress shim into the registry, instead of being dropped.
 *
 * Before phase-92 brix_tpc_progress_emit() discarded its bytes_total argument
 * ((void) bytes_total) and brix_tpc_registry_update() had no field to store it,
 * so native + threaded transfers published bytes_total == 0 forever and the
 * dashboard's progress-% was always 0. This unit drives the REAL registry
 * (registry.o), which is SHM-backed: we let the module's own shm_init run but
 * satisfy brix_shm_table_alloc() from the heap (calloc of the exact size the
 * registry asks for, so we never need the private table layout), and stub the
 * shmtx as a no-op since the unit is single-threaded.
 *
 * Asserts:
 *   success:      update_progress refreshes bytes_total (positive) + bytes_done;
 *                 the progress-emit shim forwards the same total end-to-end.
 *   idempotency:  a plain update() and an update_progress(total=0) both LEAVE the
 *                 stored total untouched (0 must never clobber a real total).
 *   error/sec:    an unknown id DECLINEs and mutates nothing; id==0 is a no-op OK.
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

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* The registry only ever locks the process-local mutex; single-threaded here. */
void ngx_shmtx_lock(ngx_shmtx_t *mtx) { (void) mtx; }
void ngx_shmtx_unlock(ngx_shmtx_t *mtx) { (void) mtx; }

size_t
brix_shm_zone_size(size_t table_bytes)
{
    return table_bytes + 4096;   /* + one page, mirrors brix_shm_zone_size */
}

/* Return the zone the module reserves so configure() binds its static pointer. */
ngx_shm_zone_t *
ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name, size_t size, void *tag)
{
    (void) cf; (void) name; (void) size; (void) tag;
    return &g_zone;
}

/* Satisfy the slot-table allocation from the heap: the registry passes us the
 * exact sizeof(table), so we never depend on the private layout. Always a fresh
 * (zeroed) table; publish it via shm_zone->data exactly like the real helper. */
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
add_native_zero_total(void)
{
    /* Native/threaded TPC registers with a literal 0 total (the O-2 bug). */
    brix_tpc_transfer_t t;
    ngx_str_t           src = ngx_string("root://src//f");
    ngx_str_t           dst = ngx_string("/data/f");

    memset(&t, 0, sizeof(t));
    t.protocol   = BRIX_TPC_PROTO_STREAM;
    t.direction  = BRIX_TPC_DIR_PULL;
    t.src_url    = src;
    t.dst_path   = dst;
    t.bytes_total = 0;
    t.state      = BRIX_TPC_STATE_ACTIVE;
    return brix_tpc_registry_add(&t, NULL, 0 /* no concurrency cap */);
}

int
main(void)
{
    const brix_tpc_transfer_t *snap;
    uint64_t                    id;

    /* Bring up the real registry: reserve the zone, then run its shm_init. */
    assert(brix_tpc_registry_configure(NULL) == NGX_OK);
    assert(g_zone.init != NULL);
    assert(g_zone.init(&g_zone, NULL) == NGX_OK);

    id = add_native_zero_total();
    assert(id != 0);
    snap = brix_tpc_registry_find(id);
    assert(snap != NULL && snap->bytes_total == 0 && snap->bytes_done == 0);

    /* success — a mid-flight total (curl dltotal) now reaches the registry. */
    assert(brix_tpc_registry_update_progress(id, 100, 5000,
                                             BRIX_TPC_STATE_ACTIVE, NULL)
           == NGX_OK);
    snap = brix_tpc_registry_find(id);
    assert(snap->bytes_total == 5000 && snap->bytes_done == 100);

    /* idempotency — a plain update() carries no total and must NOT reset it. */
    assert(brix_tpc_registry_update(id, 200, BRIX_TPC_STATE_ACTIVE, NULL)
           == NGX_OK);
    snap = brix_tpc_registry_find(id);
    assert(snap->bytes_total == 5000 && snap->bytes_done == 200);

    /* idempotency — update_progress with total==0 also leaves the total alone. */
    assert(brix_tpc_registry_update_progress(id, 300, 0,
                                             BRIX_TPC_STATE_ACTIVE, NULL)
           == NGX_OK);
    snap = brix_tpc_registry_find(id);
    assert(snap->bytes_total == 5000 && snap->bytes_done == 300);

    /* the progress-emit shim (transports' entry point) forwards the total too. */
    assert(brix_tpc_progress_emit(id, 400, 7000, BRIX_TPC_STATE_DONE, NULL)
           == NGX_OK);
    snap = brix_tpc_registry_find(id);
    assert(snap->bytes_total == 7000 && snap->bytes_done == 400
           && snap->state == BRIX_TPC_STATE_DONE);

    /* error / security-negative — unknown id changes nothing and DECLINEs; a
     * zero id is a benign no-op that must not touch the live transfer. */
    assert(brix_tpc_registry_update_progress(id + 12345, 1, 1,
                                             BRIX_TPC_STATE_ERROR, NULL)
           == NGX_DECLINED);
    assert(brix_tpc_progress_emit(0, 1, 1, BRIX_TPC_STATE_ERROR, NULL) == NGX_OK);
    snap = brix_tpc_registry_find(id);
    assert(snap->bytes_total == 7000 && snap->bytes_done == 400
           && snap->state == BRIX_TPC_STATE_DONE);

    printf("test_tpc_progress_total: ALL PASS\n");
    return 0;
}
