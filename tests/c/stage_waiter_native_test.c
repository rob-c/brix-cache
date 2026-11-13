/* Recall waiter lifetime tests using real nginx shared memory and process IDs. */
#include "fs/xfer/stage_waiter.h"
#include "core/compat/shm_slots.h"
#include "core/ngx_brix_module.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static ngx_int_t
park(const char *id, int fd, unsigned generation, ngx_pid_t worker)
{
    const u_char stream[] = {0x12, 0x34};
    return brix_stage_waiter_add(id, 0, stream, fd, generation, worker, 1000);
}

static void
unavailable(void)
{
    assert(park("unconfigured", -1, 1, ngx_pid) == NGX_ERROR);
    brix_stage_waiter_deliver("unconfigured", 1);
    brix_stage_waiter_poll_local();
    brix_stage_waiter_drop_conn(-1, 1);
}

/* Use the canonical helper to bind the slab lock before fresh allocation.
 * The temporary bootstrap record is private; init allocates the real table. */
static ngx_shm_zone_t *
configure(ngx_conf_t *cf, unsigned capacity)
{
    ngx_shm_zone_t *zone;
    ngx_slab_pool_t *slab;
    int bootstrap = 0;
    assert(brix_stage_waiter_configure(cf, capacity) == NGX_OK);
    unavailable();
    zone = cf->cycle->shared_memory.part.elts;
    assert(ngx_shm_alloc(&zone->shm) == NGX_OK);
    slab = (ngx_slab_pool_t *) zone->shm.addr;
    slab->end = zone->shm.addr + zone->shm.size;
    slab->min_shift = 3;
    slab->addr = zone->shm.addr;
    ngx_slab_init(slab);
    assert(brix_shm_table_alloc(zone, &bootstrap, 0, &slab->mutex, NULL) == &bootstrap);
    assert(zone->init(zone, NULL) == NGX_OK);
    assert(zone->data != &bootstrap && zone->data == slab->data);
    assert(park(NULL, -1, 1, ngx_pid) == NGX_ERROR);
    brix_stage_waiter_deliver(NULL, 1);
    return zone;
}

static void
fill(unsigned capacity, const char *id, ngx_pid_t worker)
{
    for (unsigned i = 0; i < capacity; i++) {
        assert(park(id, -1, i, worker) == NGX_OK);
    }
    assert(park("overflow", -1, capacity, worker) == NGX_AGAIN);
}

/* A matching completion releases all rows, including multiple 16-row batches;
 * wrong IDs and wrong connection generations cannot release someone else's row. */
static void
lifecycle(ngx_shm_zone_t *zone, unsigned capacity, const char *mode)
{
    fill(capacity, "recall", ngx_pid);
    brix_stage_waiter_deliver("other", 1);
    brix_stage_waiter_drop_conn(-1, capacity);
    assert(park("still-full", -1, 9, ngx_pid) == NGX_AGAIN);
    if (!strcmp(mode, "reload")) {
        void *previous = zone->data;
        assert(zone->init(zone, previous) == NGX_OK);
        assert(zone->data == previous);
        assert(park("still-full", -1, 9, ngx_pid) == NGX_AGAIN);
    }
    brix_stage_waiter_drop_conn(-1, 0);
    assert(park("recall", -1, 0, ngx_pid) == NGX_OK);
    assert(park("still-full", -1, 9, ngx_pid) == NGX_AGAIN);
    brix_stage_waiter_deliver("recall", 1);
    fill(capacity, "reused", ngx_pid);
    ngx_current_msec += 1001;
    if (!strcmp(mode, "expire-poll")) { brix_stage_waiter_poll_local(); }
    fill(capacity, "after-expiry", ngx_pid);
}

/* A parent may mark another worker's rows ready, but only that actual worker
 * may claim them. Pipes establish ordering without scheduler-delay guesses. */
static void
cross_worker(unsigned capacity)
{
    int start[2], done[2], status;
    char byte = 'x';
    assert(pipe(start) == 0 && pipe(done) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(start[1]); close(done[0]);
        ngx_pid = getpid();
        assert(read(start[0], &byte, 1) == 1);
        brix_stage_waiter_poll_local();
        assert(write(done[1], &byte, 1) == 1);
        close(start[0]); close(done[1]);
        exit(0);
    }
    close(start[0]); close(done[1]);
    fill(capacity, "remote-worker", child);
    brix_stage_waiter_drop_conn(-1, 0);
    brix_stage_waiter_deliver("remote-worker", 1);
    assert(park("not-mine", -1, 0, ngx_pid) == NGX_AGAIN);
    assert(write(start[1], &byte, 1) == 1);
    assert(read(done[0], &byte, 1) == 1);
    fill(capacity, "released-by-owner", ngx_pid);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(start[1]); close(done[0]);
}

/* Invalid/recycled connection records cannot receive a delayed response. */
static void
stale_connection(ngx_cycle_t *cycle, const char *mode)
{
    ngx_connection_t connection = {0};
    ngx_connection_t *files[8] = {0};
    ngx_stream_session_t session = {0};
    brix_ctx_t *ctx = calloc(1, sizeof(*ctx));
    void *contexts[1] = {ctx};
    assert(ctx != NULL);
    extern ngx_module_t ngx_stream_brix_module;
    ngx_stream_brix_module.ctx_index = 0;
    connection.fd = 7; connection.number = 42; connection.data = &session;
    session.ctx = contexts;
    ctx->state = XRD_ST_WAITING_FRM;
    if (!strcmp(mode, "recycled")) { connection.number = 43; }
    if (!strcmp(mode, "destroyed")) { connection.destroyed = 1; }
    if (!strcmp(mode, "no-session")) { connection.data = NULL; }
    if (!strcmp(mode, "no-context")) { contexts[0] = NULL; }
    if (!strcmp(mode, "dead-context")) { ctx->destroyed = 1; }
    if (!strcmp(mode, "wrong-state")) { ctx->state = XRD_ST_REQ_HEADER; }
    cycle->connections = &connection; cycle->connection_n = 1;
    if (!strcmp(mode, "missing-fd")) { connection.fd = 8; }
    if (!strcmp(mode, "files-recycled")) {
        cycle->files = files; cycle->files_n = 8; files[7] = &connection;
        connection.fd = 8;
    }
    assert(park("stale", 7, 42, ngx_pid) == NGX_OK);
    brix_stage_waiter_deliver("stale", 1);
    assert(park("replacement", -1, 1, ngx_pid) == NGX_OK);
    free(ctx);
}

int
main(int argc, char **argv)
{
    ngx_log_t log = {0};
    ngx_cycle_t cycle = {.log = &log};
    ngx_conf_t cf = {.cycle = &cycle, .log = &log};
    assert(argc == 3);
    ngx_time_init(); ngx_pid = getpid(); ngx_os_argv = argv; ngx_cycle = &cycle;
    assert(ngx_os_init(&log) == NGX_OK);
    cf.pool = cycle.pool = ngx_create_pool(16384, &log);
    assert(cf.pool != NULL);
    assert(ngx_list_init(&cycle.shared_memory, cf.pool, 1, sizeof(ngx_shm_zone_t)) == NGX_OK);
    unavailable();
    unsigned requested = (unsigned) strtoul(argv[2], NULL, 10);
    unsigned capacity = requested == 0 ? 256 : requested;
    if (capacity > 4096) { capacity = 4096; }
    ngx_shm_zone_t *zone = configure(&cf, requested);
    if (!strcmp(argv[1], "cross-worker")) { cross_worker(capacity); }
    else if (capacity == 1) { stale_connection(&cycle, argv[1]); }
    else { lifecycle(zone, capacity, argv[1]); }
    ngx_shm_free(&zone->shm);
    ngx_destroy_pool(cf.pool);
    return 0;
}
