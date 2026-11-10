/* The staged VFS lifecycle retains policy, ownership and exact error results. */
#include "fs/vfs/vfs_internal.h"
#include "fs/vfs/vfs_backend_registry.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    unsigned opens, writes, commits, aborts, barriers;
    int error, armed;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Fail one allocation after context setup.
 * WHY: Refused construction must not dispatch storage.
 * HOW: Consume the selected fault; all later allocations remain real. */
void *__real_ngx_pcalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && mode("allocation")) { state()->armed = 0; return NULL; }
    return __real_ngx_pcalloc(pool, size);
}
void *__real_ngx_palloc(ngx_pool_t *, size_t);
void *__wrap_ngx_palloc(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && mode("clone")) { state()->armed = 0; return NULL; }
    return __real_ngx_palloc(pool, size);
}

/* WHAT: Inject storage exhaustion into a real POSIX temporary file.
 * WHY: Failed reservation must close and remove the unpublished object.
 * HOW: Delegate every normal request to the actual reserve implementation. */
ngx_int_t __real_brix_vfs_fd_reserve(ngx_log_t *, int, off_t);
ngx_int_t __wrap_brix_vfs_fd_reserve(ngx_log_t *log, int fd, off_t size)
{
    if (mode("reserve")) { assert(fd >= 0 && size == 6); errno = state()->error; return NGX_ERROR; }
    return __real_brix_vfs_fd_reserve(log, fd, size);
}
int __wrap_brix_vfs_backend_durable(const char *root) { assert(root); return 1; }

/* WHAT: Supply a finite object-store staged session.
 * WHY: The VFS must own dispatch, policy and lifetime around each backend call.
 * HOW: Check exact logical names, writes and handle identity at the driver seam. */
static brix_sd_staged_t *stage_open(brix_sd_instance_t *inst, const char *key,
    mode_t permissions, off_t declared, int *error)
{
    assert(inst->state == state() && !strcmp(key, "/object"));
    assert(permissions == 0600 && declared == 6); state()->opens++;
    if (mode("driver-open")) { *error = state()->error; return NULL; }
    return (brix_sd_staged_t *) state();
}
static ssize_t stage_write(brix_sd_staged_t *handle, const void *bytes, size_t length, off_t offset)
{
    assert(handle == (brix_sd_staged_t *) state());
    assert(length == 3 && (!memcmp(bytes, "abc", 3) || !memcmp(bytes, "def", 3)));
    assert(offset == 0 || offset == 3); state()->writes++;
    if (mode("short")) { return 2; }
    if (mode("driver-write")) { errno = state()->error; return -1; }
    return (ssize_t) length;
}
static ngx_int_t stage_commit(brix_sd_staged_t *handle, brix_sd_precond_t *pre)
{
    assert(handle == (brix_sd_staged_t *) state() && pre == NULL); state()->commits++;
    if (mode("driver-commit")) { errno = state()->error; return NGX_ERROR; }
    return NGX_OK;
}
static void stage_abort(brix_sd_staged_t *handle)
{ assert(handle == (brix_sd_staged_t *) state()); state()->aborts++; }
static ngx_int_t sync_publish(brix_sd_instance_t *inst, const char *key)
{
    assert(inst->state == state() && !strcmp(key, "/object")); state()->barriers++;
    if (mode("barrier")) { errno = state()->error; return NGX_ERROR; }
    return NGX_OK;
}

/* WHAT: Check safe queries and invalid calls without dispatch.
 * WHY: Missing handles must never create or publish an object.
 * HOW: Exercise the public empty-handle contract with exact errno checks. */
static void invalid(void)
{
    assert(brix_vfs_staged_fd(NULL) == NGX_INVALID_FILE);
    assert(!brix_vfs_staged_is_driver(NULL));
    assert(!strcmp(brix_vfs_staged_tmp_path(NULL), ""));
    assert(brix_vfs_staged_write(NULL, "x", 1, 0) == NGX_ERROR && errno == EINVAL);
    assert(brix_vfs_staged_commit(NULL, NULL) == NGX_ERROR && errno == EINVAL);
    brix_vfs_staged_t empty = {0};
    assert(brix_vfs_staged_commit(&empty, NULL) == NGX_ERROR && errno == EINVAL);
    brix_vfs_staged_abort(NULL, 1);
}

/* WHAT: Verify each post-open lifetime and publication outcome.
 * WHY: A short write or refused commit cannot consume the backend handle.
 * HOW: Use exact dispatch counts and repeated abort to detect lost ownership. */
static void finish(brix_vfs_staged_t *st, int driver, int expected)
{
    fixture *f = state();
    assert(brix_vfs_staged_is_driver(st) == (unsigned) driver);
    assert((brix_vfs_staged_fd(st) == NGX_INVALID_FILE) == driver);
    assert((strlen(brix_vfs_staged_tmp_path(st)) == 0) == driver);
    if (mode("readonly-write")) { st->ctx->mutation_policy = brix_vfs_policy_from_write_enable(0); }
    ngx_int_t rc = brix_vfs_staged_write(st, "def", 3, 3);
    if (mode("short") || mode("driver-write") || mode("readonly-write")) {
        assert(rc == NGX_ERROR && errno == expected);
        brix_vfs_staged_abort(st, 1); brix_vfs_staged_abort(st, 1);
        assert(f->commits == 0 && f->aborts == (unsigned) driver); return;
    }
    assert(rc == NGX_OK && brix_vfs_staged_write(st, "abc", 3, 0) == NGX_OK);
    if (driver) { assert(st->driver_total == 6); }
    if (mode("readonly-commit")) { st->ctx->mutation_policy = brix_vfs_policy_from_write_enable(0); }
    if (mode("missing-path")) { st->ctx->resolved.resolved.data = NULL; }
    brix_sd_precond_t pre = {0}; brix_sd_precond_t *condition = NULL;
    if (mode("match-missing") || mode("match-mismatch")) {
        pre.kind = BRIX_SD_PRECOND_MATCH_META; pre.size = 7; condition = &pre;
    }
    rc = brix_vfs_staged_commit(st, condition);
    assert(rc == (expected ? NGX_ERROR : NGX_OK));
    if (expected) { assert(errno == expected); }
    brix_vfs_staged_abort(st, 1); brix_vfs_staged_abort(st, 1);
    if (driver) {
        unsigned consumed = f->commits && !mode("driver-commit");
        assert(f->aborts == !consumed);
        assert(f->barriers == consumed);
    }
}

int main(int argc, char **argv)
{
    assert(argc == 6); fixture f = {0}; f.mode = argv[3]; f.error = atoi(argv[4]);
    int expected = atoi(argv[5]), driver = !strcmp(argv[2], "driver");
    ngx_cycle = &f.cycle; ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_ERR, .file = &file}; f.cycle.log = &log;
    ngx_time_init(); ngx_os_argv = argv; assert(ngx_os_init(&log) == NGX_OK);
    f.cycle.pool = ngx_create_pool(16384, &log); assert(f.cycle.pool); invalid();
    char path[PATH_MAX]; assert(snprintf(path, sizeof(path), "%s/object", argv[1]) < PATH_MAX);
    brix_sd_driver_t drv = {.name = "fixture", .staged_open = stage_open,
        .staged_write = stage_write, .staged_commit = stage_commit,
        .staged_abort = stage_abort, .sync_publish = sync_publish};
    brix_sd_instance_t inst = {.driver = &drv, .state = &f, .log = &log};
    brix_vfs_ctx_t ctx;
    brix_vfs_ctx_init(&ctx, f.cycle.pool, &log, BRIX_PROTO_ROOT, argv[1], NULL,
        brix_vfs_policy_from_write_enable(!mode("readonly")), 0, NULL, path);
    ctx.declared_size = 6; if (driver) { ctx.sd = &inst; }
    if (mode("null-root")) { ctx.root_canon = NULL; }
    char long_key[PATH_MAX + 32]; memset(long_key, 'x', sizeof(long_key));
    long_key[0] = '/'; long_key[sizeof(long_key) - 1] = 0;
    if (mode("long-key")) {
        ctx.resolved.resolved.data = (u_char *) long_key;
        ctx.resolved.resolved.len = strlen(long_key);
    }
    if (mode("unconfined")) { ctx.resolved.is_confined = 0; }
    f.armed = 1; int error = 0;
    brix_vfs_staged_t *st = brix_vfs_staged_open(&ctx, 0600, 8, &error);
    if (!st) {
        assert(expected && error == expected && errno == expected);
        assert(f.opens == (unsigned) mode("driver-open"));
        assert(f.writes == 0 && f.commits == 0 && f.aborts == 0);
    } else {
        assert(st->ctx != &ctx && st->ctx->root_canon != argv[1]);
        assert(st->ctx->resolved.resolved.data != (u_char *) path);
        finish(st, driver, expected);
    }
    printf("opens=%u writes=%u commits=%u aborts=%u barriers=%u\n",
        f.opens, f.writes, f.commits, f.aborts, f.barriers);
    ngx_destroy_pool(f.cycle.pool); ngx_cycle = NULL; return 0;
}
