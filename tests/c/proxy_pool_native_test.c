/* Exercise the dormant dynamic pool through its public API and real locks. */
#include "protocols/webdav/proxy_pool.h"
#include "net/dns/dns.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
mode_is(const char *mode)
{
    const char *value = getenv("BRIX_POOL_TEST_MODE");
    return value != NULL && strcmp(value, mode) == 0;
}

/* These two seams delimit the external configuration and resolver services.
 * The table, nginx URL parser, state machine and all locking stay real. */
char *
__wrap_brix_dns_backend_prepare(ngx_conf_t *cf)
{
    (void) cf;
    return mode_is("prepare-error") ? NGX_CONF_ERROR : NGX_CONF_OK;
}

ngx_int_t
__wrap_brix_dns_resolve(brix_dns_req_t *req)
{
    brix_proxy_be_snapshot_t row;
    brix_proxy_be_snapshot_t rows[BRIX_PROXY_POOL_SLOTS];
    brix_proxy_be_pick_t pick;
    ngx_uint_t count;
    struct sockaddr_in *address = (struct sockaddr_in *) &req->addrs[0].ss;

    count = brix_proxy_pool_snapshot(rows, BRIX_PROXY_POOL_SLOTS);
    assert(count > 0);
    row = rows[count - 1];
    assert(row.state == BRIX_PROXY_BE_RESOLVING);
    if (count == 1) {
        assert(brix_proxy_pool_select(&pick) == NGX_DECLINED);
    }
    if (mode_is("start-error")) {
        req->error = "injected resolver startup failure";
        return NGX_ERROR;
    }
    if (mode_is("drain-during-dns")) {
        assert(brix_proxy_pool_drain(row.id));
        assert(brix_proxy_pool_undrain(row.id));
        assert(brix_proxy_pool_snapshot(&row, 1) == 1);
        assert(row.state == BRIX_PROXY_BE_RESOLVING);
        assert(brix_proxy_pool_drain(row.id));
    }
    if (mode_is("remove-during-dns")) {
        assert(brix_proxy_pool_remove(row.id) == BRIX_PROXY_REMOVE_REMOVED);
    }
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address->sin_port = htons(req->port);
    req->addrs[0].len = mode_is("oversized-address") ? 4096 : sizeof(*address);
    req->naddrs = 1;
    req->rc = mode_is("resolve-error") ? NGX_ERROR : NGX_OK;
    req->error = "injected lookup failure";
    req->handler(req);
    return NGX_OK;
}

static void
check_unavailable(ngx_pool_t *pool, ngx_log_t *log)
{
    brix_proxy_be_pick_t pick;
    brix_proxy_be_snapshot_t row;
    assert(brix_proxy_pool_add("http://127.0.0.1", 1, pool, log, NULL)
           == NGX_DECLINED);
    assert(brix_proxy_pool_select(&pick) == NGX_DECLINED);
    assert(brix_proxy_pool_snapshot(&row, 1) == 0);
    assert(brix_proxy_pool_remove(1) == BRIX_PROXY_REMOVE_NOT_FOUND);
    assert(brix_proxy_pool_drain(1) == 0);
    assert(brix_proxy_pool_undrain(1) == 0);
    assert(brix_proxy_pool_in_flight(1) == -1);
    brix_proxy_pool_dec_in_flight(1);
}

static ngx_shm_zone_t *
configure_pool(ngx_conf_t *cf)
{
    ngx_shm_zone_t *zone;
    brix_proxy_be_table_t *table;
    ngx_slab_pool_t *slab;
    size_t offset = ngx_align(sizeof(*slab), NGX_ALIGNMENT);

    assert(brix_proxy_pool_configure(cf) == NGX_OK);
    assert(brix_proxy_pool_configure(cf) == NGX_OK);
    zone = cf->cycle->shared_memory.part.elts;
    check_unavailable(cf->pool, cf->log);
    assert(ngx_shm_alloc(&zone->shm) == NGX_OK);
    slab = (ngx_slab_pool_t *) zone->shm.addr;
    slab->addr = zone->shm.addr;
    /* Present a previous cycle's table, in real shared memory. Reload must
     * preserve its metadata and bind the canonical slab-header lock. */
    table = (brix_proxy_be_table_t *) (zone->shm.addr + offset);
    assert(offset + sizeof(*table) + 32 * sizeof(table->slots[0]) < zone->shm.size);
    table->capacity = BRIX_PROXY_POOL_SLOTS;
    table->next_id = 1;
    assert(zone->init(zone, table) == NGX_OK);
    assert(zone->data == table);
    assert(table->capacity == BRIX_PROXY_POOL_SLOTS);
    return zone;
}

static void
check_weighted(ngx_conf_t *cf)
{
    uint32_t first, second;
    unsigned counts[3] = {0};
    brix_proxy_be_pick_t pick;
    brix_proxy_be_snapshot_t rows[2];
    unsigned index;

    assert(brix_proxy_pool_add("http://127.0.0.1", 0, cf->pool, cf->log,
                               &first) == NGX_OK);
    assert(setenv("BRIX_POOL_TEST_MODE", "multiple", 1) == 0);
    assert(brix_proxy_pool_add("https://[::1]:8443/path", 2, cf->pool, cf->log,
                               &second) == NGX_OK);
    assert(first == 1 && second == 2);
    for (index = 0; index < 300; index++) {
        assert(brix_proxy_pool_select(&pick) == NGX_OK);
        assert(pick.id == first || pick.id == second);
        counts[pick.id]++;
        assert(brix_proxy_pool_in_flight(pick.id) == 1);
        brix_proxy_pool_dec_in_flight(pick.id);
        brix_proxy_pool_dec_in_flight(pick.id);
        assert(brix_proxy_pool_in_flight(pick.id) == 0);
    }
    assert(counts[1] == 100 && counts[2] == 200);
    assert(brix_proxy_pool_snapshot(rows, 2) == 2);
    assert(strcmp(rows[0].host, "127.0.0.1") == 0);
    assert(strcmp(rows[1].host, "[::1]:8443") == 0 && rows[1].ssl == 1);
    assert(brix_proxy_pool_snapshot(rows, 1) == 1);
    assert(brix_proxy_pool_snapshot(rows, 0) == 0);
}

static void
check_drain(ngx_conf_t *cf)
{
    uint32_t id;
    brix_proxy_be_pick_t pick;
    assert(brix_proxy_pool_add("https://127.0.0.1", 1, cf->pool, cf->log,
                               &id) == NGX_OK);
    assert(brix_proxy_pool_select(&pick) == NGX_OK);
    assert(strcmp(pick.url_base, "https://127.0.0.1") == 0);
    assert(brix_proxy_pool_remove(id) == BRIX_PROXY_REMOVE_BUSY);
    assert(brix_proxy_pool_drain(id));
    assert(brix_proxy_pool_select(&pick) == NGX_DECLINED);
    brix_proxy_pool_dec_in_flight(id);
    assert(brix_proxy_pool_undrain(id));
    assert(brix_proxy_pool_select(&pick) == NGX_OK);
    brix_proxy_pool_dec_in_flight(id);
    assert(brix_proxy_pool_remove(id) == BRIX_PROXY_REMOVE_REMOVED);
    assert(brix_proxy_pool_remove(id) == BRIX_PROXY_REMOVE_NOT_FOUND);
    assert(brix_proxy_pool_drain(id) == 0);
    assert(brix_proxy_pool_undrain(id) == 0);
    brix_proxy_pool_dec_in_flight(id);
    assert(brix_proxy_pool_in_flight(id) == -1);
}

static void
check_capacity(ngx_conf_t *cf)
{
    uint32_t id = 0, previous;
    unsigned index;
    assert(setenv("BRIX_POOL_TEST_MODE", "multiple", 1) == 0);
    for (index = 0; index < BRIX_PROXY_POOL_SLOTS; index++) {
        assert(brix_proxy_pool_add("http://127.0.0.1", 1, cf->pool, cf->log,
                                   &id) == NGX_OK);
    }
    assert(brix_proxy_pool_add("http://127.0.0.1", 1, cf->pool, cf->log,
                               NULL) == NGX_ERROR);
    previous = id;
    assert(brix_proxy_pool_remove(id) == BRIX_PROXY_REMOVE_REMOVED);
    assert(brix_proxy_pool_add("http://127.0.0.1", 1, cf->pool, cf->log,
                               &id) == NGX_OK);
    assert(id > previous);
}

static void
check_dns_failure(ngx_conf_t *cf)
{
    uint32_t id;
    brix_proxy_be_pick_t pick;
    brix_proxy_be_snapshot_t row;
    assert(brix_proxy_pool_add("http://missing.invalid", 1, cf->pool, cf->log,
                               &id) == NGX_OK);
    assert(brix_proxy_pool_select(&pick) == NGX_DECLINED);
    if (mode_is("remove-during-dns")) {
        assert(brix_proxy_pool_snapshot(&row, 1) == 0);
        return;
    }
    assert(brix_proxy_pool_snapshot(&row, 1) == 1);
    assert(row.state == (mode_is("drain-during-dns")
                        ? BRIX_PROXY_BE_DRAINING : BRIX_PROXY_BE_DEAD));
    assert(brix_proxy_pool_in_flight(id) == 0);
}

int
main(int argc, char **argv)
{
    ngx_log_t log = {0};
    ngx_cycle_t cycle = {0};
    ngx_conf_t cf = {0};
    ngx_shm_zone_t *zone;

    assert(argc >= 2);
    assert(setenv("BRIX_POOL_TEST_MODE", argv[1], 1) == 0);
    ngx_time_init();
    ngx_pid = getpid();
    ngx_os_argv = argv;
    cycle.log = &log;
    ngx_cycle = &cycle;
    assert(ngx_os_init(&log) == NGX_OK);
    cycle.pool = ngx_create_pool(16384, &log);
    assert(cycle.pool != NULL);
    assert(ngx_list_init(&cycle.shared_memory, cycle.pool, 1,
                         sizeof(ngx_shm_zone_t)) == NGX_OK);
    cf.cycle = &cycle;
    cf.pool = cycle.pool;
    cf.log = &log;
    check_unavailable(cf.pool, cf.log);
    if (mode_is("prepare-error")) {
        assert(brix_proxy_pool_configure(&cf) == NGX_ERROR);
        ngx_destroy_pool(cycle.pool);
        return 0;
    }
    zone = configure_pool(&cf);
    if (mode_is("weighted")) {
        check_weighted(&cf);
    } else if (mode_is("drain")) {
        check_drain(&cf);
    } else if (mode_is("capacity")) {
        check_capacity(&cf);
    } else if (mode_is("invalid-url")) {
        assert(argc == 3);
        assert(brix_proxy_pool_add(argv[2], 1, cf.pool, cf.log, NULL) == NGX_ERROR);
    } else {
        check_dns_failure(&cf);
    }
    ngx_shm_free(&zone->shm);
    ngx_destroy_pool(cycle.pool);
    return 0;
}
