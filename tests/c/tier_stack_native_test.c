/* Storage-tier factory configuration and composition ordering contracts. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/tier/tier.h"
#include "fs/backend/cache/sd_cache.h"
#include "fs/backend/stage/sd_stage.h"
#include "fs/backend/frm/sd_frm.h"
#include "fs/backend/rados/sd_ceph.h"
#include "auth/impersonate/lifecycle.h"
#include <assert.h>

typedef struct {
    brix_tier_stack_t stack;
    brix_sd_instance_t objects[5];
    const char *mode, *fault;
    unsigned created, stage, cache, chowns, identities;
    int root;
} fixture;

/* WHAT: Access the stack observer. WHY: No production hook. HOW: Cycle context. */
static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }

/* WHAT: Select a boundary failure. WHY: Test each composition exit. HOW: Name. */
static int fault(const char *name) { return !strcmp(state()->fault, name); }

/* WHAT: Supply privilege state. WHY: No real host ownership changes. HOW: Query. */
uid_t __wrap_geteuid(void) { return state()->root ? 0 : 504; }

/* WHAT: Observe the runtime owner lookup. WHY: Worker handoff must use its ids.
 * HOW: Assert unset config inputs and return explicit uid/gid or an error. */
ngx_int_t __wrap_brix_imp_worker_runtime_ids(ngx_uid_t uid, ngx_gid_t gid,
    ngx_uid_t *out_uid, ngx_gid_t *out_gid)
{
    assert(uid == (ngx_uid_t) NGX_CONF_UNSET_UINT && gid == (ngx_gid_t) NGX_CONF_UNSET_UINT);
    state()->identities++;
    if (fault("identity")) { return NGX_ERROR; }
    *out_uid = 6001; *out_gid = 6002; return NGX_OK;
}

/* WHAT: Check all pblock layout ownership changes. WHY: WAL/pack state must move.
 * HOW: Match the exact known store paths and inject harmless syscall failures. */
int __wrap_chown(const char *path, uid_t uid, gid_t gid)
{
    static const char *tails[] = {"", "/data", "/catalog.db", "/catalog.db-wal",
        "/catalog.db-shm", "/catalog.db-journal", "/pack", "/pack/.lock",
        "/catalog.bxi", "/pblock.opts"};
    fixture *f = state();
    assert(uid == 6001 && gid == 6002 && f->chowns < 10);
    assert(!strncmp(path, "/fixture/store", 14) && !strcmp(path + 14, tails[f->chowns++]));
    if (fault("missing") || fault("denied")) { errno = fault("missing") ? ENOENT : EPERM; return -1; }
    return 0;
}

/* WHAT: Inspect a local driver config. WHY: Preserve geometry and worker policy.
 * HOW: Match the declared tier fields at the actual instance factory boundary. */
static void check_local(const char *driver, void *config)
{
    if (!strcmp(driver, "block")) {
        brix_sd_block_conf_t *c = config;
        assert(!strcmp(c->device, "/fixture/store") && c->extent_size == 65536); return;
    }
    if (!strcmp(driver, "ram")) {
        brix_sd_ram_conf_t *c = config; assert(c->capacity == 1048576); return;
    }
    if (!strcmp(driver, "pblock")) {
        brix_sd_pblock_conf_t *c = config;
        assert(!strcmp(c->root, "/fixture/store") && c->block_size == 65536);
        assert(c->enforce_unprivileged == (ngx_process == NGX_PROCESS_WORKER));
        assert(c->busy_timeout_ms > 0); return;
    }
    assert(!strcmp(driver, "posix") && !strcmp(config, "/fixture/store"));
}

/* WHAT: Inspect Ceph config. WHY: Strip only one leading path slash.
 * HOW: Assert pool/default conf and prefix nullability at the SDK factory seam. */
static void check_ceph(void *config)
{
    brix_sd_ceph_conf_t *c = config;
    assert(!strcmp(c->pool, "pool") && c->conf_file == NULL);
    const char *path = state()->stack.backend.path;
    const char *expected = path[0] == '/' ? path + 1 : path;
    if (!*expected) { assert(c->key_prefix == NULL); }
    else { assert(c->key_prefix && !strcmp(c->key_prefix, expected)); }
}

/* WHAT: Allocate fixture-owned identities. WHY: Composition uses real pointer order.
 * HOW: Distinct slots expose backend/store/decorator confusion without storage I/O. */
brix_sd_instance_t *__wrap_brix_sd_instance_create(ngx_log_t *log, const char *driver,
    void *config, int *error)
{
    fixture *f = state(); unsigned slot = f->created++;
    assert(log == ngx_cycle->log && slot < 5);
    if (!strcmp(driver, "ceph")) { check_ceph(config); }
    else { check_local(driver, config); }
    printf("FACTORY %s\n", driver);
    if ((fault("backend") && slot == 0) || (fault("stage-store") && slot == 1)
        || (fault("cache-store") && slot == 2)) { *error = ENOMEM; return NULL; }
    return &f->objects[slot];
}

/* WHAT: Validate stage wrapping. WHY: The backend must stay inside the stage.
 * HOW: Assert source/store identity, service domain and exact policy address. */
brix_sd_instance_t *__wrap_brix_sd_stage_create(brix_sd_instance_t *source,
    brix_sd_instance_t *store, const brix_stage_policy_t *policy, const char *root, ngx_log_t *log)
{
    fixture *f = state(); f->stage++;
    assert(source == &f->objects[0] && store == &f->objects[1]);
    assert(store->domain == BRIX_VFS_DOMAIN_STAGE && policy == &f->stack.stage);
    assert(root == NULL && log == ngx_cycle->log);
    return fault("stage-wrap") ? NULL : &f->objects[3];
}

/* WHAT: Validate outermost cache wrapping. WHY: Cache must retain stage writes.
 * HOW: Assert decorated source and local-vs-xattr metadata root selection. */
brix_sd_instance_t *__wrap_brix_sd_cache_create(brix_sd_instance_t *source,
    brix_sd_instance_t *store, const brix_cache_policy_t *policy, const char *root, ngx_log_t *log)
{
    fixture *f = state(); f->cache++;
    assert(source == &f->objects[f->stage ? 3 : 0]);
    assert(store == &f->objects[f->stage ? 2 : 1] && store->domain == BRIX_VFS_DOMAIN_CACHE);
    assert(policy == &f->stack.cache && log == ngx_cycle->log);
    if (!strcmp(f->stack.cache_store.driver, "posix")) { assert(root && !strcmp(root, "/fixture/store")); }
    else { assert(root == NULL); }
    return fault("cache-wrap") ? NULL : &f->objects[4];
}

/* WHAT: Validate tape configuration. WHY: Query grammar must precede creation.
 * HOW: The real parser supplies depth to an observed FRM factory. */
brix_sd_instance_t *__wrap_brix_sd_frm_create_opts(const char *adapter,
    const char *path, const brix_sd_frm_opts_t *opts, ngx_log_t *log)
{
    fixture *f = state(); f->created++;
    assert(!strcmp(adapter, "pool") && !strcmp(path, "/fixture/store") && log == ngx_cycle->log);
    printf("DEPTH %u\n", opts->arc_depth); return &f->objects[0];
}

/* WHAT: Seed a tier. WHY: All driver branches need the same concrete policy.
 * HOW: Stack-owned values passed through the public builder. */
static void tier(brix_tier_cfg_t *t, const char *driver)
{
    snprintf(t->driver, sizeof(t->driver), "%s", driver);
    snprintf(t->path, sizeof(t->path), "/fixture/store");
    snprintf(t->host, sizeof(t->host), "pool");
    t->block_size = 65536; t->capacity = 1048576; t->configured = 1;
}

/* WHAT: Run stack composition. WHY: Failed construction must not be memoized.
 * HOW: Test independent enable flags and exact cached-result identity. */
static void stack_case(fixture *f, unsigned flags, int expected)
{
    brix_sd_instance_t *result; unsigned count;
    tier(&f->stack.backend, "posix"); tier(&f->stack.stage_store, "ram");
    tier(&f->stack.cache_store, fault("remote-cache") ? "ram" : "posix");
    f->stack.stage.enabled = flags & 1; f->stack.stage_store.configured = (flags & 2) != 0;
    f->stack.cache.enabled = (flags & 4) != 0; f->stack.cache_store.configured = (flags & 8) != 0;
    f->stack.backend.nearline = fault("nearline");
    assert(brix_tier_build_stack(NULL, ngx_cycle->log) == NULL);
    result = brix_tier_build_stack(&f->stack, ngx_cycle->log);
    assert((result != NULL) == expected && f->stack.composed == result);
    if (result != NULL) {
        assert(f->stage == ((flags & 3) == 3) && f->cache == ((flags & 12) == 12));
        count = f->created; assert(brix_tier_build_stack(&f->stack, ngx_cycle->log) == result);
        assert(f->created == count);
    }
}

/* WHAT: Run one factory/handoff/composition contract. WHY: Isolate side effects.
 * HOW: A cycle context owns all fake instances and precise call counters. */
int main(int argc, char **argv)
{
    fixture f = {0}; ngx_cycle_t cycle = {0}; ngx_log_t log = {0};
    brix_sd_instance_t *result; assert(argc == 6);
    f.mode = argv[1]; f.fault = argv[2]; f.root = atoi(argv[3]);
    cycle.conf_ctx = (void ****) &f; cycle.log = &log; ngx_cycle = &cycle;
    ngx_process = fault("worker") ? NGX_PROCESS_WORKER : NGX_PROCESS_MASTER;
    if (!strcmp(f.mode, "stack")) { stack_case(&f, (unsigned) atoi(argv[4]), atoi(argv[5])); }
    else if (!strcmp(f.mode, "handoff")) {
        brix_tier_pblock_hand_to_worker(fault("null-root") ? NULL : "/fixture/store", &log);
        assert(f.chowns == (unsigned) atoi(argv[5]));
    } else {
        tier(&f.stack.backend, f.mode);
        if (!strcmp(f.mode, "ceph") || !strcmp(f.mode, "rados")) {
            snprintf(f.stack.backend.path, sizeof(f.stack.backend.path), "%s", argv[4]);
        } else { snprintf(f.stack.backend.opts, sizeof(f.stack.backend.opts), "%s", argv[4]); }
        result = brix_tier_build(&f.stack.backend, &log);
        assert((result != NULL) == atoi(argv[5]));
    }
    printf("created=%u stage=%u cache=%u identities=%u chowns=%u\n",
        f.created, f.stage, f.cache, f.identities, f.chowns); return 0;
}
