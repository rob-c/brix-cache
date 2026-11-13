/* Public storage forwarders must never silently cross a denied identity boundary. */
#include "fs/backend/sd.h"
#include <assert.h>

typedef struct {
    const brix_sd_cred_t *expected;
    unsigned plain, scoped, hinted;
    brix_sd_obj_t object;
    brix_sd_staged_t staged;
    brix_sd_dir_t directory;
} fixture;

/* WHAT: Observe the selected identity boundary.
 * WHY: A refused fallback must not invoke any service-credential slot.
 * HOW: Check the exact key and credential pointer while counting dispatch. */
static fixture *observe(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred)
{
    fixture *f = inst->state; assert(!strcmp(path, "/key"));
    if (cred) { assert(cred == f->expected); f->scoped++; }
    else { f->plain++; }
    return f;
}

static brix_sd_obj_t *open_plain(brix_sd_instance_t *inst, const char *path,
    int flags, mode_t bits, int *error)
{
    assert(flags == 17 && bits == 0600); if (error) { *error = 0; }
    return &observe(inst, path, NULL)->object;
}

static brix_sd_obj_t *open_scoped(brix_sd_instance_t *inst, const char *path,
    int flags, mode_t bits, const brix_sd_cred_t *cred, int *error)
{
    assert(flags == 17 && bits == 0600); if (error) { *error = 0; }
    return &observe(inst, path, cred)->object;
}

static brix_sd_obj_t *open_hinted(brix_sd_instance_t *inst, const char *path,
    int flags, mode_t bits, const brix_sd_cred_t *cred,
    const brix_sd_open_hints_t *hints, int *error)
{
    assert(hints && hints->block_size == 4096 && flags == 17 && bits == 0600);
    if (error) { *error = 0; }
    fixture *f = observe(inst, path, cred); f->hinted++; return &f->object;
}

static brix_sd_staged_t *stage_plain(brix_sd_instance_t *inst, const char *path,
    mode_t bits, off_t size, int *error)
{
    assert(bits == 0600 && size == 8192); if (error) { *error = 0; }
    return &observe(inst, path, NULL)->staged;
}

static brix_sd_staged_t *stage_scoped(brix_sd_instance_t *inst, const char *path,
    mode_t bits, off_t size, const brix_sd_cred_t *cred, int *error)
{
    assert(bits == 0600 && size == 8192); if (error) { *error = 0; }
    return &observe(inst, path, cred)->staged;
}

static brix_sd_dir_t *dir_plain(brix_sd_instance_t *inst, const char *path, int *error)
{
    if (error) { *error = 0; }
    return &observe(inst, path, NULL)->directory;
}

static brix_sd_dir_t *dir_scoped(brix_sd_instance_t *inst, const char *path,
    int *error, const brix_sd_cred_t *cred)
{
    if (error) { *error = 0; }
    return &observe(inst, path, cred)->directory;
}

/* WHAT: Invoke one pointer-returning storage operation.
 * WHY: Errno and optional error outputs are both part of the public contract.
 * HOW: Pass distinct arguments through the unmodified inline adapter. */
static void *invoke(brix_sd_instance_t *inst, const char *operation,
    const brix_sd_cred_t *cred, int *error)
{
    if (!strcmp(operation, "open")) {
        return brix_sd_open_maybe_cred(inst, "/key", 17, 0600, cred, error);
    }
    if (!strcmp(operation, "hinted")) {
        brix_sd_open_hints_t hints = {.block_size = 4096};
        return brix_sd_open_hinted_maybe_cred(inst, "/key", 17, 0600, cred, &hints, error);
    }
    if (!strcmp(operation, "staged")) {
        return brix_sd_staged_open_maybe_cred(inst, "/key", 0600, 8192, cred, error);
    }
    assert(!strcmp(operation, "opendir"));
    return brix_sd_opendir_maybe_cred(inst, "/key", error, cred);
}

/* WHAT: Check absent optional namespace primitives.
 * WHY: Missing support must be explicit, without a fallback call or fabricated work.
 * HOW: Use an empty vtable and require the documented errno for each operation. */
static void missing_namespace(brix_sd_instance_t *inst, const brix_sd_cred_t *cred)
{
    brix_sd_stat_t st = {0}; brix_sd_unlink_batch_t batch = {0};
    brix_sd_setattr_t attr = {0}; char bytes[40]; off_t copied = 0; uint64_t evicted = 0;
    assert(brix_sd_stat_maybe_cred(inst, "/key", &st, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_unlink_maybe_cred(inst, "/key", 0, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_unlink_many_maybe_cred(inst, &batch, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_mkdir_maybe_cred(inst, "/key", 0600, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_rename_maybe_cred(inst, "/key", "/dest", 0, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_exchange_maybe_cred(inst, "/key", "/dest", cred) == NGX_ERROR && errno == ENOTSUP);
    assert(brix_sd_truncate_path_maybe_cred(inst, "/key", 1, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_setattr_maybe_cred(inst, "/key", &attr, cred) == NGX_OK);
    assert(brix_sd_getxattr_maybe_cred(inst, "/key", "user.x", bytes, 40, cred) == -1 && errno == ENOSYS);
    assert(brix_sd_listxattr_maybe_cred(inst, "/key", bytes, 40, cred) == -1 && errno == ENOSYS);
    assert(brix_sd_setxattr_maybe_cred(inst, "/key", "user.x", "a", 1, 0, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_removexattr_maybe_cred(inst, "/key", "user.x", cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_server_copy_maybe_cred(inst, "/key", "/dest", &copied, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_recall_maybe_cred(inst, "/key", bytes, cred) == NGX_ERROR && errno == ENOSYS);
    assert(brix_sd_evict_maybe_cred(inst, "/key", &evicted, cred) == NGX_ERROR && errno == ENOSYS);
}

int main(int argc, char **argv)
{
    assert(argc == 4); const char *operation = argv[1], *mode = argv[2];
    brix_sd_cred_t credential = {.bearer = "fixture-bearer", .fallback_deny = 1};
    fixture f = {.expected = &credential}; brix_sd_driver_t driver = {0};
    brix_sd_instance_t inst = {.driver = &driver, .state = &f};
    const brix_sd_cred_t *cred = !strcmp(mode, "plain") ? NULL : &credential;
    if (!strcmp(operation, "namespace")) { missing_namespace(&inst, cred); return 0; }
    int has_plain = strcmp(mode, "missing") && strcmp(mode, "scoped-only");
    int has_scoped = !strcmp(mode, "scoped") || !strcmp(mode, "scoped-only");
    if (!strcmp(mode, "allow")) { credential.fallback_deny = 0; }
    if (has_plain) {
        driver.open = open_plain; driver.staged_open = stage_plain; driver.opendir = dir_plain;
    }
    if (has_scoped) {
        driver.open_cred = open_scoped; driver.staged_open_cred = stage_scoped;
        driver.opendir_cred = dir_scoped;
    }
    if (has_plain || has_scoped) { driver.open_hinted = open_hinted; }
    int error = 99, *error_out = atoi(argv[3]) ? &error : NULL;
    void *result = invoke(&inst, operation, cred, error_out);
    int expected = !strcmp(mode, "deny") ? EACCES : (!strcmp(mode, "missing") ? ENOSYS : 0);
    if (expected) {
        assert(result == NULL && errno == expected && f.plain == 0 && f.scoped == 0);
        if (error_out) { assert(error == expected); }
    } else {
        assert(result && f.plain + f.scoped == 1 && f.scoped == (unsigned) has_scoped);
        if (error_out) { assert(error == 0); }
    }
    unsigned expected_hint = !strcmp(operation, "hinted") && (has_scoped || cred == NULL);
    assert(f.hinted == expected_hint); return 0;
}
