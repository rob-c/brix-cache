/* Real candidate collection, ordering, storage eviction and sentinel cleanup;
 * deterministic capacity and manager/cold-store boundaries observe policy. */
#include "fs/cache/evict_internal.h"
#include "fs/cache/cache_storage.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    int measured, removed, unregistered, demoted;
} fixture_t;
static fixture_t *state(void) { return (fixture_t *)ngx_cycle; }
static int mode(const char *s) { return !strcmp(state()->mode, s); }

ngx_int_t __wrap_brix_cache_usage_measure(brix_cstore_t *cs, const char *root,
    brix_cache_fs_usage_t *usage)
{
    (void)cs; assert(root); fixture_t *f = state(); f->measured++;
    if (mode("usage-error") || (mode("remeasure-error") && f->removed)) { errno = EIO; return NGX_ERROR; }
    usage->occupancy_ppm = mode("below") || f->removed >= 2 ? 100000 : 900000;
    return NGX_OK;
}
ngx_int_t __real_brix_cstore_evict(brix_cstore_t *, const char *);
ngx_int_t __wrap_brix_cstore_evict(brix_cstore_t *cs, const char *key)
{
    assert(strcmp(key, "/protected") && strcmp(key, "/busy" BRIX_CACHE_PART_SUFFIX));
    printf("removed=%s\n", key); state()->removed++;
    return __real_brix_cstore_evict(cs, key);
}
void __wrap_brix_srv_unregister_path(const char *host, uint16_t port, const char *path)
{
    assert(host && path[0] == '/'); assert(port == 1094); state()->unregistered++;
}
brix_sd_instance_t *__wrap_brix_cache_storage_decorator(const ngx_stream_brix_srv_conf_t *conf)
{ return mode("demote") ? brix_cache_storage(conf) : NULL; }
ngx_int_t __wrap_brix_sd_cache_demote(brix_sd_instance_t *inst, const char *key)
{ assert(inst && key[0] == '/'); state()->demoted++; errno = ENOSPC; return NGX_ERROR; }
const char *__real_brix_cache_state_root(const ngx_stream_brix_srv_conf_t *);
const char *__wrap_brix_cache_state_root(const ngx_stream_brix_srv_conf_t *conf)
{ return mode("no-root") ? NULL : __real_brix_cache_state_root(conf); }
ngx_int_t __real_brix_cache_collect_dir(brix_cache_evict_list_t *, const char *, ngx_log_t *);
ngx_int_t __wrap_brix_cache_collect_dir(brix_cache_evict_list_t *list, const char *key, ngx_log_t *log)
{
    ngx_int_t rc = __real_brix_cache_collect_dir(list, key, log);
    return mode("partial-scan") ? NGX_ERROR : rc;
}

int main(int argc, char **argv)
{
    assert(argc == 4); fixture_t f = {0}; f.mode = argv[2]; ngx_cycle = &f.cycle;
    ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_WARN, .file = &file}; f.cycle.log = &log;
    ngx_time_init(); ngx_os_argv = argv; assert(ngx_os_init(&log) == NGX_OK);
    f.cycle.pool = ngx_create_pool(16384, &log); assert(f.cycle.pool);
    ngx_stream_brix_srv_conf_t conf = {0}; conf.cache = 1;
    conf.cache_root = (ngx_str_t){strlen(argv[1]), (u_char *)argv[1]};
    conf.cache_eviction_threshold = 500000; conf.cache_lock_timeout = 60;
    conf.cache_max_file_size = mode("lru") ? 0 : 15; conf.manager_mode = 1;
    assert(brix_cache_storage_init(&conf, &f.cycle) == NGX_OK);
    struct sockaddr_in ipv4 = {.sin_family = AF_INET, .sin_port = htons(1094)};
    struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6, .sin6_port = htons(1094)};
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK); ipv6.sin6_addr = in6addr_loopback;
    ngx_connection_t connection = {.local_sockaddr = (void *)&ipv4, .local_socklen = sizeof(ipv4)};
    if (mode("ipv6")) { connection.local_sockaddr = (void *)&ipv6; connection.local_socklen = sizeof(ipv6); }
    brix_ctx_t *ctx = calloc(1, sizeof(*ctx)); assert(ctx);
    ctx->metrics = calloc(1, sizeof(*ctx->metrics)); assert(ctx->metrics);
    ngx_uint_t files = 99; uint64_t bytes = 99; int rc = 0;
    if (!strcmp(argv[3], "on-fill")) {
        brix_cache_fill_t *task = calloc(1, sizeof(*task)); assert(task);
        task->conf = &conf; task->ctx = ctx; task->c = &connection;
        brix_cache_evict_if_needed(task, NULL, &log); free(task);
    } else {
        rc = brix_cache_purge_to_target(&conf, ctx, &connection, NULL,
                                       500000, &log, &files, &bytes);
    }
    printf("result=%d %lu %llu %d %d %d %d %lu\n", rc, (unsigned long)files,
        (unsigned long long)bytes, f.measured, f.removed, f.unregistered, f.demoted,
        (unsigned long)ctx->metrics->cache_eviction_errors_total);
    assert(f.removed == f.unregistered);
    brix_cache_storage_cleanup(&conf); ngx_destroy_pool(f.cycle.pool);
    free(ctx->metrics); free(ctx); ngx_cycle = NULL; return 0;
}
