/* Rename and exchange retain both-name policy, credential and durability gates. */
#include "fs/vfs/vfs_internal.h"
#include "fs/vfs/vfs_backend_registry.h"
#include "core/compat/staged_file.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode, *root;
    unsigned calls, syncs, creds;
    int error, fail_sync, overwrite;
} fixture;

static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Supply the merged durability choice.
 * WHY: Both entries must flush every changed name when durability is requested.
 * HOW: Enable barriers while checking the exact fixture export. */
int __wrap_brix_vfs_backend_durable(const char *root)
{
    assert(!strcmp(root, state()->root)); return 1;
}

/* WHAT: Inject one namespace durability failure.
 * WHY: A completed rename cannot be reported durable after a failed barrier.
 * HOW: Count the selected barrier and preserve its chosen errno. */
static ngx_int_t barrier(void)
{
    fixture *f = state(); f->syncs++;
    if ((int) f->syncs == f->fail_sync) { errno = f->error; return NGX_ERROR; }
    return NGX_OK;
}

ngx_int_t __real_brix_publish_dirsync(ngx_log_t *, int, const char *, const char *);
ngx_int_t __wrap_brix_publish_dirsync(ngx_log_t *log, int fd,
    const char *root, const char *path)
{
    if (barrier() != NGX_OK) { return NGX_ERROR; }
    return __real_brix_publish_dirsync(log, fd, root, path);
}

/* WHAT: Observe the backend's two-name operation.
 * WHY: Keys must be export-relative and the operation must happen exactly once.
 * HOW: Assert both logical names, count dispatch, and optionally fail the driver. */
static ngx_int_t mutation(brix_sd_instance_t *inst, const char *a, const char *b)
{
    assert(inst->state == state()); assert(!strcmp(a, "/source"));
    assert(!strcmp(b, "/destination")); state()->calls++;
    if (mode("driver-error")) { errno = state()->error; return NGX_ERROR; }
    return NGX_OK;
}

static ngx_int_t rename_key(brix_sd_instance_t *inst, const char *a, const char *b, int no_replace)
{
    assert(no_replace == !state()->overwrite); return mutation(inst, a, b);
}

static ngx_int_t rename_cred(brix_sd_instance_t *inst, const char *a,
    const char *b, int no_replace, const brix_sd_cred_t *cred)
{
    assert(cred && !strcmp(cred->bearer, "fixture-bearer"));
    return rename_key(inst, a, b, no_replace);
}

static ngx_int_t exchange_cred(brix_sd_instance_t *inst, const char *a,
    const char *b, const brix_sd_cred_t *cred)
{
    assert(cred && !strcmp(cred->bearer, "fixture-bearer")); return mutation(inst, a, b);
}

static ngx_int_t sync_key(brix_sd_instance_t *inst, const char *key)
{
    assert(inst->state == state());
    assert(!strcmp(key, "/source") || !strcmp(key, "/destination"));
    return barrier();
}

static ngx_int_t stat_key(brix_sd_instance_t *inst, const char *key, brix_sd_stat_t *out)
{
    assert(inst->state == state() && !strcmp(key, "/destination"));
    if (mode("stat-error")) { errno = EIO; return NGX_ERROR; }
    memset(out, 0, sizeof(*out)); out->is_dir = mode("directory"); return NGX_OK;
}

/* WHAT: Materialize a bounded caller credential or an explicit refusal.
 * WHY: A namespace mutation must never fall back to the service identity on denial.
 * HOW: Supply only the credential seam; policy, key conversion and dispatch stay real. */
ngx_int_t __wrap_brix_vfs_ns_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use, int *error)
{
    assert(ctx && store); state()->creds++;
    if (mode("credential-error")) { *error = state()->error; return NGX_ERROR; }
    cred->bearer = "fixture-bearer"; *use = 1; return NGX_OK;
}

/* WHAT: Seed a real POSIX namespace.
 * WHY: The durability failure path must still reflect the already-applied mutation.
 * HOW: Create disjoint, byte-identifiable source and destination files. */
static void seed(const char *path, const char *bytes)
{
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600); assert(fd >= 0);
    assert(write(fd, bytes, strlen(bytes)) == (ssize_t) strlen(bytes)); assert(!close(fd));
}

/* WHAT: Exercise the low-level worker rename adapter.
 * WHY: Directory metadata and non-overwrite flags must survive driver dispatch.
 * HOW: Use the actual key conversion and check the post-rename directory result. */
static void worker(brix_sd_instance_t *inst, const char *a, const char *b, int expected)
{
    int was_dir = 99;
    ngx_int_t rc = brix_vfs_rename_path(inst, state()->cycle.log, state()->root,
        NULL, mode("bad-source") ? NULL : a, mode("bad-target") ? NULL : b,
        state()->overwrite, &was_dir);
    assert(rc == (expected ? NGX_ERROR : NGX_OK));
    if (expected) { assert(errno == expected); }
    if (!mode("bad-source") && !mode("bad-target")) {
        assert(was_dir == (expected ? 0 : mode("directory")));
    }
}

/* WHAT: Apply public-entry input variations.
 * WHY: Invalid second names and read-only policy must precede backend work.
 * HOW: Change only the selected public input after normal context initialization. */
static const brix_path_result_t *second(brix_vfs_ctx_t *ctx, brix_path_result_t *dst)
{
    if (mode("null-target")) { return NULL; }
    if (mode("null-root")) { ctx->root_canon = NULL; }
    if (mode("unconfined")) { dst->is_confined = 0; }
    if (mode("empty-target")) { dst->resolved.data = NULL; }
    if (mode("outside")) {
        dst->resolved.data = (u_char *) "/outside/export"; dst->resolved.len = 15;
    }
    return dst;
}

int main(int argc, char **argv)
{
    assert(argc == 9); fixture f = {0}; ngx_cycle = &f.cycle;
    f.root = argv[1]; f.mode = argv[4]; f.error = atoi(argv[5]);
    f.fail_sync = atoi(argv[6]); int expected = atoi(argv[7]); f.overwrite = atoi(argv[8]);
    ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_ERR, .file = &file};
    f.cycle.log = &log; ngx_time_init(); ngx_os_argv = argv;
    assert(ngx_os_init(&log) == NGX_OK);
    f.cycle.pool = ngx_create_pool(16384, &log); assert(f.cycle.pool);
    char a[PATH_MAX], b[PATH_MAX];
    assert(snprintf(a, sizeof(a), "%s/source", f.root) < PATH_MAX);
    assert(snprintf(b, sizeof(b), "%s/destination", f.root) < PATH_MAX);
    brix_sd_driver_t drv = {.caps = BRIX_SD_CAP_DIRS_WRITE, .rename = rename_key,
        .exchange = mutation, .rename_cred = rename_cred, .exchange_cred = exchange_cred,
        .stat = stat_key, .sync_publish = sync_key};
    brix_sd_instance_t inst = {.driver = &drv, .state = &f, .log = &log};
    if (mode("no-capability")) { drv.caps = 0; }
    if (mode("no-operation")) { drv.rename = NULL; drv.exchange = NULL; }
    if (mode("no-stat")) { drv.stat = NULL; }
    int remote = !strcmp(argv[3], "driver");
    if (!remote) { seed(a, "source-bytes"); seed(b, "destination-bytes"); }
    if (!strcmp(argv[2], "worker")) {
        worker(remote ? &inst : NULL, a, b, expected);
    } else {
        brix_vfs_ctx_t ctx;
        brix_vfs_ctx_init(&ctx, f.cycle.pool, &log, BRIX_PROTO_ROOT, f.root,
            NULL, brix_vfs_policy_from_write_enable(!mode("readonly")), 0, NULL, a);
        if (remote) { ctx.sd = &inst; }
        if (mode("credential") || mode("credential-error") || mode("readonly")) {
            ctx.storage_cred_dir = "/fixture-credentials";
        }
        brix_path_result_t dst = {.resolved = {strlen(b), (u_char *) b}, .is_confined = 1};
        const brix_path_result_t *target = second(&ctx, &dst);
        ngx_int_t rc = !strcmp(argv[2], "rename") ? brix_vfs_rename(&ctx, target, 1)
                                                   : brix_vfs_exchange(&ctx, target);
        assert(rc == (expected ? NGX_ERROR : NGX_OK));
        if (expected) { assert(errno == expected); }
    }
    if (mode("readonly")) { assert(f.calls == 0 && f.creds == 0 && f.syncs == 0); }
    if (mode("credential-error")) { assert(f.calls == 0 && f.creds >= 1 && f.syncs == 0); }
    if (f.fail_sync) { assert(f.syncs == (unsigned) f.fail_sync); }
    if (mode("credential")) { assert(f.calls == 1 && f.creds >= 1); }
    printf("calls=%u syncs=%u\n", f.calls, f.syncs);
    ngx_destroy_pool(f.cycle.pool); return 0;
}
