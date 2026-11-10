/* Build-independent io_uring kill switch over real shared memory and timers. */
#include "core/ngx_brix_module.h"
#include "core/aio/uring.h"
#include "core/compat/shm_slots.h"
#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/wait.h>
#include <unistd.h>

ngx_shm_zone_t *__real_ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
                                           size_t size, void *tag);
void *__real_ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);

/* WHAT: Select one explicit initialization failure.
 * WHY: Failure tests must not affect unrelated process setup.
 * HOW: Read the fixture-only switch armed around the tested call. */
static int fault(const char *name)
{
    const char *selected = getenv("BRIX_URING_ADMIN_TEST_FAULT");
    return selected != NULL && strcmp(selected, name) == 0;
}

/* WHAT: Refuse zone registration when requested.
 * WHY: Failed registration must leave the public API safely unavailable.
 * HOW: Return NULL once armed; otherwise use nginx's actual zone list. */
ngx_shm_zone_t *__wrap_ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
                                           size_t size, void *tag)
{
    if (fault("zone")) { return NULL; }
    return __real_ngx_shared_memory_add(cf, name, size, tag);
}

/* WHAT: Refuse allocation of the shared flag.
 * WHY: An uninitialized zone cannot expose an apparent enabled flag.
 * HOW: Keep the real slab allocator except for the explicit failure case. */
void *__wrap_ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    if (fault("slab")) { return NULL; }
    return __real_ngx_slab_alloc(pool, size);
}

/* WHAT: Check the public API before usable shared memory exists.
 * WHY: Stub builds and initialization failures must be clean no-ops.
 * HOW: Require a NULL pointer and DECLINED mutation with a disabled admin gate. */
static void unavailable(void)
{
    assert(brix_uring_killswitch_ptr() == NULL);
    assert(brix_uring_killswitch_get() == 0);
    assert(brix_uring_killswitch_set(1) == NGX_DECLINED);
}

/* WHAT: Initialize the production zone with canonical slab locking.
 * WHY: Reload and process-sharing tests need actual mapped storage.
 * HOW: Register, map and initialize the slab; bind its mutex through the helper. */
static ngx_shm_zone_t *configure(ngx_conf_t *cf, const char *kind)
{
    if (strcmp(kind, "zone") == 0) {
        assert(setenv("BRIX_URING_ADMIN_TEST_FAULT", kind, 1) == 0);
        assert(brix_uring_killswitch_configure(cf) == NGX_ERROR);
        unavailable();
        assert(unsetenv("BRIX_URING_ADMIN_TEST_FAULT") == 0);
    }
    assert(brix_uring_killswitch_configure(cf) == NGX_OK);
    assert(brix_uring_killswitch_configure(cf) == NGX_OK);
    ngx_shm_zone_t *zone = cf->cycle->shared_memory.part.elts;
    unavailable();
    assert(ngx_shm_alloc(&zone->shm) == NGX_OK);
    ngx_slab_pool_t *slab = (ngx_slab_pool_t *)zone->shm.addr;
    slab->end = zone->shm.addr + zone->shm.size;
    slab->min_shift = 3; slab->addr = zone->shm.addr;
    ngx_slab_init(slab);
    int bootstrap = 0;
    assert(brix_shm_table_alloc(zone, &bootstrap, 0, &slab->mutex, NULL) == &bootstrap);
    zone->data = NULL;
    if (strcmp(kind, "slab") == 0) {
        assert(setenv("BRIX_URING_ADMIN_TEST_FAULT", kind, 1) == 0);
        assert(zone->init(zone, NULL) == NGX_ERROR);
        unavailable();
        assert(unsetenv("BRIX_URING_ADMIN_TEST_FAULT") == 0);
    }
    assert(zone->init(zone, NULL) == NGX_OK);
    assert(zone->data != NULL && zone->data == slab->data);
    return zone;
}

/* WHAT: Prove reload and reattachment preserve a disabled flag.
 * WHY: Reinitialization must not silently re-enable an incident-disabled backend.
 * HOW: Reuse the exact stored pointer through both zone-init paths. */
static void reload_zone(ngx_shm_zone_t *zone)
{
    void *flag = zone->data;
    assert(brix_uring_killswitch_set(17) == NGX_OK);
    assert(brix_uring_killswitch_get() == 1);
    assert(zone->init(zone, flag) == NGX_OK && zone->data == flag);
    zone->data = NULL; zone->shm.exists = 1;
    assert(zone->init(zone, NULL) == NGX_OK && zone->data == flag);
    assert(brix_uring_killswitch_get() == 1);
    assert(brix_uring_killswitch_set(0) == NGX_OK);
    assert(brix_uring_killswitch_get() == 0);
}

/* WHAT: Observe a child worker's mutation in the parent.
 * WHY: A process-local flag would leave other workers running the backend.
 * HOW: Fork after mapping, change the flag, wait and inspect the shared value. */
static void cross_worker(void)
{
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(brix_uring_killswitch_set(1) == NGX_OK);
        exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(brix_uring_killswitch_get() == 1);
}

/* WHAT: Retrieve the sole real nginx maintenance timer.
 * WHY: Idempotent arming must not create duplicate periodic work.
 * HOW: Inspect the timer tree's only node and recover its owning event. */
static ngx_event_t *only_timer(void)
{
    ngx_rbtree_node_t *node = ngx_event_timer_rbtree.root;
    assert(node != ngx_event_timer_rbtree.sentinel);
    assert(node->left == ngx_event_timer_rbtree.sentinel);
    assert(node->right == ngx_event_timer_rbtree.sentinel);
    ngx_event_t *event = (ngx_event_t *)((u_char *)node - offsetof(ngx_event_t, timer));
    assert(event->timer_set && event->cancelable && event->data != NULL);
    return event;
}

/* WHAT: Exercise panic-file mirroring and periodic maintenance.
 * WHY: Existing files must disable promptly; removal must restore the switch.
 * HOW: Drive actual timer expiry around a private file and inspect shared state. */
static void timers(ngx_cycle_t *cycle, const char *path, const char *kind)
{
    ngx_str_t name = {strlen(path), (u_char *)path};
    if (strcmp(kind, "panic") == 0) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0 && close(fd) == 0);
        assert(brix_uring_panicfile_arm(cycle, &name) == NGX_OK);
    }
    assert(brix_uring_maint_arm(cycle) == NGX_OK);
    ngx_event_t *event = only_timer();
    assert(brix_uring_maint_arm(cycle) == NGX_OK && only_timer() == event);
    ngx_current_msec += 2;
    ngx_event_expire_timers();
    assert(only_timer() == event && ngx_event_find_timer() == 2000);
    if (strcmp(kind, "panic") == 0) {
        assert(brix_uring_killswitch_get() == 1);
        ngx_current_msec += 2000; ngx_event_expire_timers();
        assert(brix_uring_killswitch_get() == 1);
        assert(unlink(path) == 0);
        ngx_current_msec += 2000; ngx_event_expire_timers();
        assert(brix_uring_killswitch_get() == 0);
    }
    ngx_del_timer(event);
}

/* WHAT: Ignore absent or oversized panic paths without arming work.
 * WHY: Invalid configuration must not read beyond the supplied path buffer.
 * HOW: Use NULL, empty and deliberately over-limit counted strings. */
static void invalid_paths(ngx_cycle_t *cycle)
{
    ngx_str_t empty = ngx_null_string;
    ngx_str_t oversized = {PATH_MAX, (u_char *)"x"};
    assert(brix_uring_panicfile_arm(cycle, NULL) == NGX_OK);
    assert(brix_uring_panicfile_arm(cycle, &empty) == NGX_OK);
    assert(brix_uring_panicfile_arm(cycle, &oversized) == NGX_OK);
    assert(ngx_event_find_timer() == NGX_TIMER_INFINITE);
}

/* WHAT: Run one kill-switch contract with real nginx memory and timer primitives.
 * WHY: The control plane must remain testable without creating a kernel ring.
 * HOW: Initialize once, drive the selected state transition and release resources. */
int main(int argc, char **argv)
{
    assert(argc == 3);
    ngx_log_t log = {0};
    ngx_cycle_t cycle = {.log = &log};
    ngx_conf_t cf = {.cycle = &cycle, .log = &log};
    ngx_time_init(); ngx_pid = getpid(); ngx_os_argv = argv; ngx_cycle = &cycle;
    assert(ngx_os_init(&log) == NGX_OK && ngx_event_timer_init(&log) == NGX_OK);
    cf.pool = cycle.pool = ngx_create_pool(16384, &log);
    assert(cf.pool != NULL);
    assert(ngx_list_init(&cycle.shared_memory, cf.pool, 1, sizeof(ngx_shm_zone_t)) == NGX_OK);
    unavailable();
    assert(brix_uring_admin_enabled() == 0);
    brix_uring_admin_set_enabled(1); assert(brix_uring_admin_enabled() == 1);
    brix_uring_admin_set_enabled(0); assert(brix_uring_admin_enabled() == 0);
    invalid_paths(&cycle);
    ngx_shm_zone_t *zone = configure(&cf, argv[1]);
    assert(brix_uring_killswitch_get() == 0);
    if (!strcmp(argv[1], "cross-worker")) { cross_worker(); }
    else if (!strcmp(argv[1], "reload")) { reload_zone(zone); }
    else { timers(&cycle, argv[2], argv[1]); }
    ngx_shm_free(&zone->shm);
    ngx_destroy_pool(cf.pool);
    return 0;
}
