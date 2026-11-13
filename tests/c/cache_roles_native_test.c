/* Cache role setup and lazy lookup retain real POSIX instances and fd ownership. */
#include "fs/cache/cache_storage.h"
#include <assert.h>

typedef struct { ngx_cycle_t cycle; const char *mode; int borrowed_fd; } fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
brix_sd_instance_t *__real_brix_sd_posix_borrow_instance(ngx_pool_t *, ngx_log_t *, int, const char *);
brix_sd_instance_t *__wrap_brix_sd_posix_borrow_instance(ngx_pool_t *pool, ngx_log_t *log, int fd, const char *root)
{
    state()->borrowed_fd = fd;
    if (mode("borrow-error")) { errno = ENOMEM; return NULL; }
    return __real_brix_sd_posix_borrow_instance(pool, log, fd, root);
}
ngx_int_t __real_brix_cstore_init(brix_cstore_t *, brix_sd_instance_t *, const char *,
    int, size_t, int, ngx_log_t *);
ngx_int_t __wrap_brix_cstore_init(brix_cstore_t *cs, brix_sd_instance_t *inst, const char *root,
    int metadata, size_t capacity, int batch, ngx_log_t *log)
{
    if (mode("cstore-error")) { errno = ENOMEM; return NGX_ERROR; }
    return __real_brix_cstore_init(cs, inst, root, metadata, capacity, batch, log);
}
static void keys(ngx_stream_brix_srv_conf_t *conf, const char *path)
{
    char key[128] = {0};
    if (mode("disabled")) { conf->cache_root.len = 0; }
    int rc = brix_cache_key(conf, path, key, mode("small") ? 1 : sizeof(key));
    const char *under = brix_cache_key_under_root(conf, mode("null") ? NULL : path);
    printf("%d|%s|%s\n", rc, rc ? "-" : key, under ? under : "-");
}
static void lazy(const char *root)
{
    const char *path = mode("null") ? NULL : mode("empty") ? "" : root;
    assert(brix_cache_state_by_root(path) == NULL);
    brix_sd_instance_t *inst = brix_cache_storage_by_root(path);
    if (mode("borrow-error")) { assert(fcntl(state()->borrowed_fd, F_GETFD) == -1 && errno == EBADF); }
    if (inst) {
        assert(brix_cache_storage_by_root(path) == inst && brix_cache_state_by_root(path) == inst);
        assert(!strcmp(brix_cache_state_root_by_root(path), path));
        assert(close(state()->borrowed_fd) == 0);
    }
    printf("%d\n", inst != NULL);
}
static void roles(ngx_stream_brix_srv_conf_t *conf, const char *stage)
{
    conf->cache_state_root = (ngx_str_t){strlen(stage), (u_char *)stage};
    conf->cache_wt_stage_root = conf->cache_state_root;
    int rc = brix_cache_storage_init(conf, &state()->cycle);
    printf("%d %d %d %d\n", rc, brix_cache_storage(conf) != NULL,
        brix_cache_state_storage(conf) != NULL, brix_cache_wt_stage(conf) != NULL);
    assert(brix_cache_source_inst(conf) == NULL && brix_cache_wt_stage_sd_inst(conf) == NULL);
    int fds[] = {conf->cache_rootfd, conf->cache_state_rootfd, conf->cache_wt_stage_rootfd};
    brix_cache_storage_cleanup(conf); brix_cache_storage_cleanup(conf);
    assert(!brix_cache_state_storage(conf) && !brix_cache_wt_stage(conf));
    for (size_t i = 0; i < 3; i++) { if (fds[i] >= 0) { assert(fcntl(fds[i], F_GETFD) == -1 && errno == EBADF); } }
}
int main(int argc, char **argv)
{
    assert(argc == 6); fixture f = {0}; f.mode = argv[2]; f.borrowed_fd = -1; ngx_cycle = &f.cycle;
    ngx_log_t log = {0}; ngx_open_file_t file = {.fd=STDERR_FILENO}; log.file = &file;
    f.cycle.log = &log; ngx_os_argv = argv; ngx_time_init(); assert(ngx_os_init(&log) == NGX_OK);
    f.cycle.pool = ngx_create_pool(16384, &log); assert(f.cycle.pool);
    ngx_stream_brix_srv_conf_t conf = {0};
    snprintf(conf.common.root_canon, sizeof(conf.common.root_canon), "%s", argv[3]);
    conf.cache_root = (ngx_str_t){strlen(argv[4]), (u_char *)argv[4]};
    if (!strcmp(argv[1], "key")) { keys(&conf, argv[5]); }
    else if (!strcmp(argv[1], "lazy")) { lazy(argv[4]); }
    else { assert(!strcmp(argv[1], "roles")); roles(&conf, argv[5]); }
    ngx_destroy_pool(f.cycle.pool); ngx_cycle = NULL; return 0;
}
