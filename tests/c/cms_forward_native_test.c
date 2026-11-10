/* Real CMS wire decoder/planner and namespace dispatcher, with observed slots. */
#include "core/ngx_brix_module.h"
#include "net/cms/cms_internal.h"
#include "net/cms/recv_internal.h"
#include "net/cms/node_fsxeq.h"
#include "fs/vfs/vfs_backend_registry.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_stream_brix_srv_conf_t conf;
    ngx_brix_cms_ctx_t context;
    brix_sd_driver_t driver;
    brix_sd_instance_t instance;
    brix_sd_obj_t object;
    const char *mode, *path;
    unsigned code, calls, opens, closes, overrides, errors;
    char message[256];
} fixture;

static fixture *state(void) { return (fixture *)ngx_cycle; }

/* WHAT: Observe one actual driver-slot invocation. WHY: Refused ops must never
 * reach storage. HOW: Validate the exact decoded path and inject a stable errno. */
static ngx_int_t operation(brix_sd_instance_t *instance, const char *path)
{
    fixture *f = state(); assert(instance == &f->instance && !strcmp(path, f->path));
    f->calls++;
    if (!strcmp(f->mode, "failure")) { errno = ENOSPC; return NGX_ERROR; }
    return NGX_OK;
}

static ngx_int_t remove_path(brix_sd_instance_t *instance, const char *path, int directory)
{
    assert(directory == (state()->code == CMS_RR_RMDIR)); return operation(instance, path);
}
static ngx_int_t make_directory(brix_sd_instance_t *instance, const char *path, mode_t mode)
{
    assert(mode == 0750); return operation(instance, path);
}
static ngx_int_t move_path(brix_sd_instance_t *instance, const char *path, const char *dest, int exclusive)
{
    assert(!strcmp(dest, "/destination") && !exclusive); return operation(instance, path);
}
static ngx_int_t set_mode(brix_sd_instance_t *instance, const char *path, const brix_sd_setattr_t *attr)
{
    assert(attr->set_mode && attr->mode == 0750); return operation(instance, path);
}

/* WHAT: Observe truncate object lifetime. WHY: Failed truncate must close once
 * and preserve its errno. HOW: Return a fixture object and poison close errno. */
static brix_sd_obj_t *open_object(brix_sd_instance_t *instance, const char *path,
                                 int flags, mode_t mode, int *error)
{
    fixture *f = state(); assert(instance == &f->instance && !strcmp(path, f->path));
    assert(flags == BRIX_SD_O_WRITE && mode == 0); f->opens++;
    if (!strcmp(f->mode, "open-fail") || !strcmp(f->mode, "open-zero")) {
        *error = !strcmp(f->mode, "open-fail") ? EACCES : 0; return NULL;
    }
    return &f->object;
}
static ngx_int_t truncate_object(brix_sd_obj_t *object, off_t length)
{
    assert(object == &state()->object && length == 17);
    return operation(&state()->instance, state()->path);
}
static ngx_int_t close_object(brix_sd_obj_t *object)
{
    assert(object == &state()->object); state()->closes++; errno = EBADF; return NGX_ERROR;
}

/* WHAT: Select a non-POSIX backend or the real confined POSIX leg.
 * WHY: Both routes share policy and reply semantics. HOW: Return only this
 * process's explicitly installed driver; default mode exercises driver identity. */
brix_sd_instance_t *__wrap_brix_vfs_backend_resolve(const char *root, ngx_log_t *log)
{
    fixture *f = state(); assert(!strcmp(root, f->conf.common.root_canon) && log == &f->log);
    if (!strncmp(f->mode, "posix", 5)) { return NULL; }
    if (!strcmp(f->mode, "default")) { f->instance.driver = brix_sd_default_driver(); }
    return &f->instance;
}

/* WHAT: Observe the recursive namespace seam. WHY: MKPATH delegates to the VFS.
 * HOW: Assert the carried writable policy and decoded mode before returning. */
int __wrap_brix_vfs_export_mkpath(const brix_vfs_export_op_ctx_t *op,
                                 const char *path, mode_t mode)
{
    assert(op->mutation_policy == brix_vfs_policy_from_write_enable(1) && mode == 0750);
    return operation(&state()->instance, path);
}

/* WHAT: Observe configured operator override. WHY: It must run after policy and
 * replace storage dispatch. HOW: Take only the explicit override case. */
ngx_int_t __wrap_brix_cms_fsxeq_dispatch(ngx_brix_cms_ctx_t *ctx, u_char code,
    uint32_t sid, const brix_cms_node_plan_t *plan, int *taken)
{
    fixture *f = state(); assert(ctx == &f->context && sid == 42 && code == f->code);
    assert(!strcmp(plan->path, f->path)); f->overrides++;
    *taken = !strcmp(f->mode, "override"); return *taken ? NGX_AGAIN : NGX_OK;
}

/* WHAT: Capture the manager-visible error. WHY: Error text, code and correlation
 * survive backend cleanup. HOW: Require the protocol EINVAL envelope and sid. */
ngx_int_t __wrap_ngx_brix_cms_send_error(ngx_brix_cms_ctx_t *ctx, uint32_t sid,
                                       uint32_t code, const char *message)
{
    fixture *f = state(); assert(ctx == &f->context && sid == 42 && code == CMS_ERR_EINVAL);
    f->errors++; snprintf(f->message, sizeof(f->message), "%s", message); return NGX_OK;
}

/* WHAT: Install a complete storage contract. WHY: Each absent slot must be
 * distinguished from failure. HOW: Remove slots only for the requested case. */
static void setup_driver(fixture *f)
{
    f->driver = (brix_sd_driver_t){.name="fixture", .open=open_object, .close=close_object,
        .ftruncate=truncate_object, .unlink=remove_path, .mkdir=make_directory,
        .rename=move_path, .setattr=set_mode};
    if (!strcmp(f->mode, "missing")) {
        f->driver.open = NULL; f->driver.unlink = NULL; f->driver.mkdir = NULL;
        f->driver.rename = NULL; f->driver.setattr = NULL;
    }
    if (!strcmp(f->mode, "no-truncate")) { f->driver.ftruncate = NULL; }
    if (!strcmp(f->mode, "no-close")) { f->driver.close = NULL; }
    f->instance.driver = &f->driver;
}

/* WHAT: Decode and apply a real forwarded frame. WHY: Codec, plan, policy and
 * storage ownership must agree. HOW: Use the repository encoder and dispatcher. */
int main(int argc, char **argv)
{
    assert(argc == 5); fixture f = {0}; f.mode = argv[1]; f.code = atoi(argv[2]); f.path = argv[4];
    ngx_cycle = &f.cycle; f.cycle.log = &f.log; ngx_time_init();
    f.cycle.pool = ngx_create_pool(8192, &f.log); assert(f.cycle.pool);
    f.context.cycle = &f.cycle; f.context.conf = &f.conf;
    assert(strlen(argv[3]) < sizeof(f.conf.common.root_canon));
    strcpy(f.conf.common.root_canon, argv[3]);
    f.conf.common.allow_write = strcmp(f.mode, "readonly") != 0;
    f.conf.rootfd = open(argv[3], O_RDONLY | O_DIRECTORY); assert(f.conf.rootfd >= 0);
    setup_driver(&f);
    brix_cms_fwd_fields_t fields = {.ident="fixture", .path=f.path, .path2="/destination",
        .mode=f.code == CMS_RR_TRUNC ? "17" : "0750"};
    if (!strcmp(f.mode, "bad-mode")) { fields.mode = "invalid"; }
    u_char payload[1024]; int length = brix_cms_rrdata_encode(f.code, &fields, payload, sizeof(payload));
    assert(length > 0);
    if (!strcmp(f.mode, "bad-frame")) { length = 1; }
    int rootfd = f.conf.rootfd;
    if (!strcmp(f.mode, "no-export")) { f.conf.rootfd = -1; }
    ngx_int_t result = cms_node_exec_forward(&f.context, f.code, 42, payload, (size_t)length);
    printf("result=%ld calls=%u opens=%u closes=%u overrides=%u errors=%u\n%s\n",
        (long)result, f.calls, f.opens, f.closes, f.overrides, f.errors, f.message);
    close(rootfd); ngx_destroy_pool(f.cycle.pool); return 0;
}
