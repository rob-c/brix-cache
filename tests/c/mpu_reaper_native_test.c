/* Real directory scans preserve live uploads and reject escaped namespace entries. */
#include "protocols/s3/s3.h"
#include "protocols/s3/multipart_internal.h"
#include "core/compat/fs_walk.h"
#include <assert.h>

typedef struct { ngx_cycle_t cycle; const char *mode; } fixture;

static int mode(const char *name)
{
    return !strcmp(((fixture *) ngx_cycle)->mode, name);
}

/* WHAT: Supply the already-authorized request's export context.
 * WHY: The reaper's storage, scan and confinement are under test.
 * HOW: Build the same real VFS context from fixture-owned configuration. */
void __wrap_s3_build_vfs_ctx(ngx_http_request_t *r, const char *path,
    ngx_http_s3_loc_conf_t *conf, brix_vfs_ctx_t *ctx)
{
    brix_vfs_ctx_init(ctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        conf->common.root_canon, NULL, brix_vfs_policy_from_write_enable(1), 0, NULL, path);
}

brix_vfs_dir_t *__real_brix_vfs_opendir_quiet(brix_vfs_ctx_t *, int *);
/* WHAT: Refuse a directory scan. WHY: Opportunistic cleanup must be fail-open.
 * HOW: Return a finite EIO only for the selected case. */
brix_vfs_dir_t *__wrap_brix_vfs_opendir_quiet(brix_vfs_ctx_t *ctx, int *error)
{
    if (mode("opendir")) { errno = EIO; if (error) { *error = EIO; } return NULL; }
    return __real_brix_vfs_opendir_quiet(ctx, error);
}

ngx_int_t __real_brix_vfs_probe(brix_vfs_ctx_t *, int, brix_vfs_stat_t *);
/* WHAT: Refuse metadata. WHY: An unreadable entry must never be guessed stale.
 * HOW: Preserve real no-follow probes unless the explicit fault is armed. */
ngx_int_t __wrap_brix_vfs_probe(brix_vfs_ctx_t *ctx, int nofollow, brix_vfs_stat_t *st)
{
    assert(nofollow);
    if (mode("probe")) { errno = EACCES; return NGX_ERROR; }
    return __real_brix_vfs_probe(ctx, nofollow, st);
}

ngx_int_t __real_brix_fs_remove_tree_confined(ngx_log_t *, const char *, const char *);
/* WHAT: Refuse recursive cleanup. WHY: Failed removals must not count as reaped.
 * HOW: Otherwise retain the genuine confined tree-removal helper. */
ngx_int_t __wrap_brix_fs_remove_tree_confined(ngx_log_t *log, const char *root, const char *path)
{
    if (mode("remove")) { errno = EACCES; return NGX_ERROR; }
    return __real_brix_fs_remove_tree_confined(log, root, path);
}

/* WHAT: Reap one private parent directory. WHY: The count must reflect storage.
 * HOW: Invoke the public helper with real request lifetime and explicit bounds. */
int main(int argc, char **argv)
{
    assert(argc == 6); fixture f = {0}; ngx_log_t log = {0};
    f.mode = argv[2]; ngx_cycle = &f.cycle; f.cycle.log = &log; ngx_time_init();
    f.cycle.pool = ngx_create_pool(8192, &log); assert(f.cycle.pool);
    ngx_connection_t connection = {.log = &log};
    ngx_http_request_t request = {.pool = f.cycle.pool, .connection = &connection};
    ngx_http_s3_loc_conf_t conf = {0};
    assert(strlen(argv[1]) < sizeof(conf.common.root_canon));
    strcpy(conf.common.root_canon, argv[1]);
    const char *path = !strcmp(argv[3], "<null>") ? NULL : argv[3];
    assert(s3_mpu_reap_stale(&request, &conf, path, atoi(argv[4])) == atoi(argv[5]));
    ngx_destroy_pool(f.cycle.pool); return 0;
}
