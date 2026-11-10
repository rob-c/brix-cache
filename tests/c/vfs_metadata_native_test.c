/* Metadata mutations retain policy precedence and credential-scoped dispatch. */
#include "fs/vfs/vfs_internal.h"
#include "fs/vfs/vfs_backend_registry.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode, *operation;
    brix_sd_instance_t *instance;
    unsigned calls, credentials, stats;
    int error;
} fixture;
/* WHAT: Access this process fixture. WHY: Avoid added globals. HOW: Borrow its cycle prefix. */
static fixture *state(void) { return (fixture *) ngx_cycle; }
/* WHAT: Match one scenario. WHY: Isolate finite faults. HOW: Compare the caller-owned mode. */
static int selected(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Select the private backend. WHY: Exercise real recursive dispatch. HOW: Return the fixture-owned instance. */
brix_sd_instance_t *__wrap_brix_vfs_backend_resolve(const char *root, ngx_log_t *log)
{
    (void) root; (void) log; return state()->instance;
}

/* WHAT: Acquire or refuse a credential. WHY: Retain policy precedence. HOW: Supply a scoped bearer at the acquisition seam. */
ngx_int_t __wrap_brix_vfs_ns_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use, int *error)
{
    assert(ctx && store); state()->credentials++;
    if (selected("credential-error")) { *error = state()->error; return NGX_ERROR; }
    cred->bearer = "metadata-user"; *use = 1; return NGX_OK;
}

/* WHAT: Observe a backend mutation. WHY: Verify exact dispatch. HOW: Check relative keys and inject the chosen errno. */
static ngx_int_t mutation(brix_sd_instance_t *inst, const char *path)
{
    fixture *f = state(); assert(inst == f->instance);
    assert(!strcmp(path, "/parent") || !strcmp(path, "/parent/leaf"));
    f->calls++;
    if (selected("driver-error") || selected("exists-file") || selected("exists-dir")
        || selected("exists-stat-error")) {
        errno = f->error; return NGX_ERROR;
    }
    return NGX_OK;
}

/* WHAT: Check directory mode. WHY: prevent argument loss. HOW: validate mode before recording the mutation. */
static ngx_int_t mkdir_key(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    assert(mode == 0751); return mutation(inst, path);
}
/* WHAT: Check caller identity. WHY: prevent service-identity fallback. HOW: validate bearer then delegate. */
static ngx_int_t mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    assert(cred && !strcmp(cred->bearer, "metadata-user"));
    return mkdir_key(inst, path, mode);
}
/* WHAT: Check metadata values. WHY: prevent dropped attributes. HOW: validate mode and timestamp then record. */
static ngx_int_t setattr_key(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    assert(attr && attr->set_mode && attr->mode == 0751);
    if (!strcmp(state()->operation, "setattr")) {
        assert(attr->set_times && attr->mtime.tv_sec == 1234567890);
    }
    return mutation(inst, path);
}
/* WHAT: Check scoped metadata credentials. WHY: prevent identity loss. HOW: validate bearer then delegate. */
static ngx_int_t setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    assert(cred && !strcmp(cred->bearer, "metadata-user"));
    return setattr_key(inst, path, attr);
}
/* WHAT: Report existing leaf type. WHY: distinguish files from directories. HOW: count the probe and return the chosen state. */
static ngx_int_t stat_key(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    assert(inst == state()->instance && !strcmp(path, "/parent/leaf"));
    state()->stats++;
    if (selected("exists-stat-error")) { errno = EIO; return NGX_ERROR; }
    memset(out, 0, sizeof(*out)); out->is_dir = selected("exists-dir"); return NGX_OK;
}
/* WHAT: Check identity on the leaf probe. WHY: keep recursive mkdir scoped. HOW: validate bearer before stat. */
static ngx_int_t stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    assert(cred && !strcmp(cred->bearer, "metadata-user")); return stat_key(inst, path, out);
}

/* WHAT: Invoke a public metadata entry. WHY: Retain real policy and translation. HOW: Dispatch the selected operation. */
static ngx_int_t perform(brix_vfs_ctx_t *ctx, unsigned parents)
{
    fixture *f = state();
    if (!strcmp(f->operation, "mkdir")) { return brix_vfs_mkdir(ctx, 0751, parents); }
    if (!strcmp(f->operation, "chmod")) { return brix_vfs_chmod(ctx, 0751); }
    brix_sd_setattr_t attr = {.set_mode = 1, .mode = 0751, .set_times = 1,
        .atime = {1234567890, 0}, .mtime = {1234567890, 0}};
    return brix_vfs_setattr(ctx, selected("null-attributes") ? NULL : &attr);
}

/* WHAT: Run an isolated metadata case. WHY: Detect dispatch after refusal. HOW: Initialize a typed context and verify outcome counters. */
int main(int argc, char **argv)
{
    assert(argc == 8);
    fixture f = {0}; ngx_cycle = &f.cycle;
    f.mode = argv[3]; f.operation = argv[2]; f.error = atoi(argv[4]);
    unsigned parents = (unsigned) atoi(argv[5]); int expected = atoi(argv[6]);
    int credential = atoi(argv[7]);
    ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_ERR, .file = &file};
    f.cycle.log = &log; ngx_time_init(); ngx_os_argv = argv;
    assert(ngx_os_init(&log) == NGX_OK);
    f.cycle.pool = ngx_create_pool(16384, &log); assert(f.cycle.pool);
    brix_sd_driver_t drv = {.caps = BRIX_SD_CAP_DIRS_WRITE,
        .mkdir = mkdir_key, .mkdir_cred = mkdir_cred, .stat = stat_key,
        .stat_cred = stat_cred, .setattr = setattr_key, .setattr_cred = setattr_cred};
    brix_sd_instance_t inst = {.driver = &drv, .state = &f, .log = &log};
    f.instance = &inst;
    if (selected("no-capability") || selected("readonly")) { drv.caps = 0; }
    if (selected("no-operation")) { drv.mkdir = NULL; drv.setattr = NULL; }
    char path[PATH_MAX + 512];
    assert(snprintf(path, sizeof(path), "%s/parent/leaf", argv[1]) < (int) sizeof(path));
    if (selected("long-path")) {
        size_t n = strlen(argv[1]); path[n] = '/';
        memset(path + n + 1, 'a', sizeof(path) - n - 2); path[sizeof(path)-1] = 0;
    }
    brix_vfs_ctx_t ctx;
    brix_vfs_ctx_init(&ctx, f.cycle.pool, &log, BRIX_PROTO_ROOT, argv[1], NULL,
        brix_vfs_policy_from_write_enable(!selected("readonly")), 0, NULL, path);
    if (credential) { ctx.storage_cred_dir = "/fixture-credentials"; }
    if (selected("null-root")) { ctx.root_canon = NULL; }
    if (selected("unconfined")) { ctx.resolved.is_confined = 0; }
    if (selected("empty-path")) { ctx.resolved.resolved.data = NULL; }
    errno = 0; ngx_int_t rc = perform(selected("null-context") ? NULL : &ctx, parents);
    if (rc != (expected ? NGX_ERROR : NGX_OK) || (expected && errno != expected)) {
        fprintf(stderr, "rc=%ld errno=%d expected=%d\n", (long) rc, errno, expected);
        abort();
    }
    if (selected("readonly")) { assert(f.calls == 0 && f.credentials == 0); }
    if (selected("credential-error")) { assert(f.calls == 0 && f.credentials >= 1); }
    printf("calls=%u credentials=%u stats=%u\n", f.calls, f.credentials, f.stats);
    ngx_destroy_pool(f.cycle.pool); return 0;
}
