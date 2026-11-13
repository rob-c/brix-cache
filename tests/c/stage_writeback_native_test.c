/* Write-back hydration, durable retry and captured identity on real POSIX stores. */
#include "core/ngx_brix_module.h"
#include "fs/backend/stage/sd_stage.h"
#include "fs/backend/stage/sd_stage_internal.h"
#include "fs/backend/posix/sd_posix_internal.h"
#include <assert.h>

typedef struct {
    const char *mode;
    brix_sd_instance_t *source, *store;
    brix_sd_driver_t source_driver, store_driver;
    unsigned recalls, flushes, queued, closed, evictions;
    int fail_flush, allocation_count, allocation_target, opened_fd;
    const char *root;
} fixture;

/* WHAT: Recover the fixture. WHY: Faults and observations belong to one invocation.
 * HOW: Decode its process-local pointer. */
static fixture *state(void)
{
    void *pointer = NULL;
    assert(sscanf(getenv("BRIX_STAGE_WB_FIXTURE"), "%p", &pointer) == 1); return pointer;
}

/* WHAT: Select one scenario. WHY: Driver wrappers must not alter unrelated cases.
 * HOW: Compare the immutable scenario label. */
static int mode(const char *name) { return !strcmp(state()->mode, name); }

void *__real_calloc(size_t, size_t);

/* WHAT: Refuse one wrapper allocation. WHY: The opened store must close on either failure.
 * HOW: Arm the counter only after the real store object has been created. */
void *__wrap_calloc(size_t count, size_t size)
{
    if (getenv("BRIX_STAGE_WB_FIXTURE") != NULL) {
        fixture *f = state();
        if (f->allocation_target && ++f->allocation_count == f->allocation_target) {
            f->allocation_target = 0; errno = ENOMEM; return NULL;
        }
    }
    return __real_calloc(count, size);
}

ngx_int_t __real_brix_stage_run_inline_cred(brix_stage_kind_t, brix_sd_instance_t *,
    const char *, brix_sd_instance_t *, const char *, const brix_stage_cred_t *);

/* WHAT: Check captured identity. WHY: Deferred work must retain the original caller.
 * HOW: Compare the saved principal and bearer after the caller mutates its buffers. */
static void check_cred(const brix_stage_cred_t *cred)
{
    if (!mode("identity")) { assert(cred == NULL); return; }
    assert(cred && !strcmp(cred->principal, "fixture-principal"));
    assert(!strcmp(cred->bearer, "fixture-bearer") && cred->deny == 1);
}

/* WHAT: Observe real transfers or refuse one. WHY: Hydration and flush have opposite owners.
 * HOW: Check direction, count the operation, and delegate the actual byte mover. */
ngx_int_t __wrap_brix_stage_run_inline_cred(brix_stage_kind_t kind,
    brix_sd_instance_t *source, const char *source_key, brix_sd_instance_t *destination,
    const char *destination_key, const brix_stage_cred_t *cred)
{
    fixture *f = state(); assert(!strcmp(source_key, "/file") && !strcmp(destination_key, "/file"));
    check_cred(cred);
    if (kind == BRIX_STAGE_RECALL) {
        assert(source == f->source && destination == f->store); f->recalls++;
        if (mode("hydrate-fail")) { errno = EREMOTEIO; return NGX_ERROR; }
    } else {
        assert(kind == BRIX_STAGE_FLUSH && source == f->store && destination == f->source);
        f->flushes++;
        if (f->fail_flush) { errno = EIO; return NGX_ERROR; }
    }
    return __real_brix_stage_run_inline_cred(kind, source, source_key, destination, destination_key, cred);
}

/* WHAT: Observe async ownership handoff. WHY: The queue must receive the durable store.
 * HOW: Validate source/destination and the export anchor, returning a finite job id. */
const char *__wrap_brix_stage_submit(brix_stage_kind_t kind, brix_sd_instance_t *source,
    const char *source_key, brix_sd_instance_t *destination, const char *destination_key,
    const brix_stage_opts_t *options)
{
    fixture *f = state(); assert(kind == BRIX_STAGE_FLUSH && source == f->store && destination == f->source);
    assert(!strcmp(source_key, "/file") && !strcmp(destination_key, "/file"));
    assert(options && options->async && !strcmp(options->export_root, f->root));
    check_cred(options->cred); f->queued++; return "finite-stage-job";
}

/* WHAT: Refuse the source probe. WHY: Offline write-back must preserve whole-object creates.
 * HOW: Supply a finite remote failure at the driver boundary. */
static ngx_int_t source_stat(brix_sd_instance_t *instance, const char *key, brix_sd_stat_t *out)
{
    assert(instance == state()->source);
    if (mode("probe-error")) { errno = EHOSTUNREACH; return NGX_ERROR; }
    return brix_sd_posix_driver.stat(instance, key, out);
}

/* WHAT: Count store closes. WHY: The adopted store object has exactly one owner.
 * HOW: Forward the actual descriptor close. */
static ngx_int_t store_close(brix_sd_obj_t *object)
{
    state()->closed++; return brix_sd_posix_driver.close(object);
}

/* WHAT: Open the real store with a scoped capability descriptor.
 * WHY: Missing optional slots must be tested without changing production globals.
 * HOW: Preserve the real object and replace only its descriptor pointer. */
static brix_sd_obj_t *store_open(brix_sd_instance_t *instance, const char *key,
                                int flags, mode_t permissions, int *error)
{
    if (mode("store-open-error")) { *error = EACCES; return NULL; }
    brix_sd_obj_t *object = brix_sd_posix_driver.open(instance, key, flags, permissions, error);
    if (object) {
        object->driver = &state()->store_driver; state()->opened_fd = object->fd;
        if (mode("shell-alloc")) { state()->allocation_target = 1; }
        if (mode("state-alloc")) { state()->allocation_target = 2; }
    }
    return object;
}

/* WHAT: Seed a private store. WHY: Hydration must preserve bytes outside partial writes.
 * HOW: Create one exact-size object through the owned directory descriptor. */
static void seed(int directory, unsigned char value)
{
    int fd = openat(directory, "file", O_WRONLY | O_CREAT | O_EXCL, 0600); assert(fd >= 0);
    unsigned char bytes[64]; memset(bytes, value, sizeof(bytes));
    assert(write(fd, bytes, sizeof(bytes)) == sizeof(bytes) && close(fd) == 0);
}

/* WHAT: Assert actual stored bytes. WHY: A successful flush must preserve the full object.
 * HOW: Read through the owned directory fd and compare length and contents exactly. */
static void check_bytes(int directory, const unsigned char *expected, size_t length)
{
    int fd = openat(directory, "file", O_RDONLY); assert(fd >= 0); unsigned char actual[128] = {0};
    assert(read(fd, actual, sizeof(actual)) == (ssize_t) length && !memcmp(actual, expected, length));
    assert(close(fd) == 0);
}

/* WHAT: Observe a clean-source eviction. WHY: The stage layer must relay credentials intact.
 * HOW: Check its key and identity, returning a finite source byte count. */
static ngx_int_t evict_cred(brix_sd_instance_t *instance, const char *key,
                           uint64_t *bytes, const brix_sd_cred_t *cred)
{
    assert(instance == state()->source && !strcmp(key, "/file"));
    if (mode("evict-credential")) { assert(cred && !strcmp(cred->principal, "evict-owner")); }
    else { assert(cred == NULL); }
    if (bytes) { *bytes = 64; }
    state()->evictions++; return NGX_OK;
}

/* WHAT: Observe service-identity eviction. WHY: Both public slots share the same ownership rule.
 * HOW: Forward to the finite observer with no credential. */
static ngx_int_t evict_plain(brix_sd_instance_t *instance, const char *key, uint64_t *bytes)
{
    return evict_cred(instance, key, bytes, NULL);
}

/* WHAT: Exercise stage eviction. WHY: Unflushed spool bytes are never disposable cache.
 * HOW: Refuse a non-empty spool; otherwise relay to the optional source primitive. */
static void check_evict(fixture *f, brix_sd_instance_t *stage, int storefd)
{
    uint64_t bytes = 999; brix_sd_cred_t cred = {.principal = "evict-owner"};
    if (mode("evict-relay") || mode("evict-credential")) {
        f->source_driver.evict = evict_plain; f->source_driver.evict_cred = evict_cred;
    }
    ngx_int_t rc = mode("evict-credential")
        ? stage->driver->evict_cred(stage, "/file", &bytes, &cred)
        : stage->driver->evict(stage, "/file", &bytes);
    if (mode("evict-busy")) {
        assert(rc == NGX_ERROR && errno == EBUSY && bytes == 0 && f->evictions == 0);
        unsigned char expected[64]; memset(expected, 'B', sizeof(expected));
        check_bytes(storefd, expected, sizeof(expected)); return;
    }
    assert(rc == NGX_OK && bytes == (f->evictions ? 64u : 0u));
    assert(f->evictions == (unsigned) (mode("evict-relay") || mode("evict-credential")));
}

/* WHAT: Rename and unlink through the decorator. WHY: Namespace changes target the source.
 * HOW: Verify both visible names before finally removing the object. */
static void namespace_rename(brix_sd_instance_t *stage)
{
    brix_sd_stat_t status;
    assert(stage->driver->rename(stage, "/file", "/moved", 0) == NGX_OK);
    assert(stage->driver->stat(stage, "/file", &status) == NGX_ERROR && errno == ENOENT);
    assert(stage->driver->stat(stage, "/moved", &status) == NGX_OK && status.size == 64);
    assert(stage->driver->sync_publish(stage, "/moved") == NGX_OK);
    assert(stage->driver->unlink(stage, "/moved", 0) == NGX_OK);
    assert(stage->driver->stat(stage, "/moved", &status) == NGX_ERROR && errno == ENOENT);
}

/* WHAT: Copy then exchange source names. WHY: The decorator must retain real atomic operations.
 * HOW: Change the copied object's size and check it follows the exchange. */
static void namespace_copy(brix_sd_instance_t *stage)
{
    off_t bytes = 0; brix_sd_stat_t status;
    assert(stage->driver->server_copy(stage, "/file", "/copy", &bytes) == NGX_OK && bytes == 64);
    /* POSIX exposes descriptor truncate, so the optional path operation refuses. */
    assert(stage->driver->truncate_path(stage, "/copy", 9) == NGX_ERROR && errno == ENOTSUP);
    assert(stage->driver->truncate_path_cred(stage, "/copy", 9, NULL) == NGX_ERROR && errno == ENOTSUP);
    int error = 0; brix_sd_instance_t *source = state()->source;
    brix_sd_obj_t *object = source->driver->open(source, "/copy", BRIX_SD_O_WRITE, 0, &error);
    assert(object && object->driver->ftruncate(object, 9) == NGX_OK);
    assert(object->driver->close(object) == NGX_OK);
    if (object->heap_shell) { free(object); }
    assert(stage->driver->exchange(stage, "/file", "/copy") == NGX_OK);
    assert(stage->driver->stat(stage, "/file", &status) == NGX_OK && status.size == 9);
    assert(stage->driver->exchange_cred(stage, "/file", "/copy", NULL) == NGX_OK);
    assert(stage->driver->stat(stage, "/file", &status) == NGX_OK && status.size == 64);
}

/* WHAT: Forward mode and xattr changes. WHY: Staging must not hide source metadata.
 * HOW: Round-trip the mode, value and xattr list, then verify removal. */
static void namespace_metadata(brix_sd_instance_t *stage)
{
    brix_sd_setattr_t attributes = {.set_mode = 1, .mode = 0640}; brix_sd_stat_t status;
    assert(stage->driver->setattr(stage, "/file", &attributes) == NGX_OK);
    assert(stage->driver->stat(stage, "/file", &status) == NGX_OK && (status.mode & 0777) == 0640);
    const char *name = "user.brix-stage-fixture"; char value[64] = {0}, names[512] = {0};
    assert(stage->driver->setxattr(stage, "/file", name, "value", 5, 0) == NGX_OK);
    assert(stage->driver->getxattr(stage, "/file", name, value, sizeof(value)) == 5);
    assert(!memcmp(value, "value", 5));
    ssize_t length = stage->driver->listxattr(stage, "/file", names, sizeof(names));
    assert(length > 0 && length < (ssize_t) sizeof(names));
    int found = 0;
    for (size_t offset = 0; offset < (size_t) length; offset += strlen(names + offset) + 1) {
        if (!strcmp(names + offset, name)) { found++; }
    }
    assert(found == 1 && stage->driver->removexattr(stage, "/file", name) == NGX_OK);
    assert(stage->driver->getxattr(stage, "/file", name, value, sizeof(value)) == -1);
}

/* WHAT: Walk the source through stage directory slots. WHY: Directory handles retain their owner.
 * HOW: Require exactly the seeded entry and close through the decorator's relay. */
static void namespace_directory(brix_sd_instance_t *stage)
{
    int error = 0; brix_sd_dir_t *directory = stage->driver->opendir(stage, "/", &error); assert(directory);
    brix_sd_dirent_t entry; unsigned count = 0; ngx_int_t rc;
    while ((rc = stage->driver->readdir(directory, &entry)) == NGX_OK) {
        assert(!strcmp(entry.name, "file") && ++count == 1);
    }
    assert(rc == NGX_DONE && count == 1 && stage->driver->closedir(directory) == NGX_OK);
}

/* WHAT: Refuse unsupported batch operations. WHY: Missing primitives must never look successful.
 * HOW: Remove the two source slots and require both decorator entries to refuse. */
static void namespace_batch(brix_sd_instance_t *stage)
{
    fixture *f = state(); f->source_driver.unlink_many = NULL; f->source_driver.unlink_many_cred = NULL;
    const char *paths[] = {"/file"}; int errors[] = {ECANCELED};
    brix_sd_unlink_batch_t batch = {.paths = paths, .n = 1, .errs = errors};
    assert(stage->driver->unlink_many(stage, &batch) == NGX_ERROR && errno == ENOTSUP);
    assert(stage->driver->unlink_many_cred(stage, &batch, NULL) == NGX_ERROR && errno == ENOTSUP);
    assert(batch.done == 0 && errors[0] == ECANCELED);
}

/* WHAT: Keep namespace requests inside the source root. WHY: A decorator cannot relax confinement.
 * HOW: Attempt an escaping rename and assert the original object is still intact. */
static void namespace_boundary(brix_sd_instance_t *stage)
{
    brix_sd_stat_t status;
    assert(stage->driver->rename(stage, "/file", "/../escape", 0) == NGX_ERROR);
    assert(stage->driver->stat(stage, "/file", &status) == NGX_OK && status.size == 64);
}

/* WHAT: Preserve read-open hints through a stage decorator. WHY: Reads belong to the source.
 * HOW: Open through the hinted slot, read the full seed and close the real object. */
static void namespace_read(brix_sd_instance_t *stage)
{
    brix_sd_open_hints_t hints = {.block_size = 65536, .prefetch_blocks = 2, .prefetch_set = 1};
    int error = 0;
    brix_sd_obj_t *object = stage->driver->open_hinted(stage, "/file", BRIX_SD_O_READ, 0, NULL, &hints, &error);
    assert(object && object->inst == state()->source); unsigned char bytes[64];
    assert(object->driver->pread(object, bytes, sizeof(bytes), 0) == sizeof(bytes));
    for (unsigned index = 0; index < sizeof(bytes); index++) { assert(bytes[index] == 'A'); }
    assert(object->driver->close(object) == NGX_OK);
    if (object->heap_shell) { free(object); }
}

/* WHAT: Run the chosen namespace contract. WHY: Each test owns a fresh source and empty spool.
 * HOW: Select one operation family from a local dispatch table. */
static void check_namespace(brix_sd_instance_t *stage)
{
    const struct { const char *name; void (*run)(brix_sd_instance_t *); } cases[] = {
        {"namespace-rename", namespace_rename}, {"namespace-copy", namespace_copy},
        {"namespace-metadata", namespace_metadata}, {"namespace-directory", namespace_directory},
        {"namespace-batch", namespace_batch}, {"namespace-boundary", namespace_boundary},
        {"namespace-read", namespace_read}
    };
    for (unsigned index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        if (mode(cases[index].name)) { cases[index].run(stage); return; }
    }
    assert(!"unknown namespace case");
}

/* WHAT: Remove one optional capability. WHY: Byte operations must report unavailable slots.
 * HOW: Mutate only the fixture's copies of the real descriptor. */
static void configure_drivers(fixture *f)
{
    f->source_driver = brix_sd_posix_driver; f->store_driver = brix_sd_posix_driver;
    f->source_driver.stat = source_stat; f->store_driver.open = store_open;
    f->store_driver.close = store_close;
    if (mode("no-source-stat")) { f->source_driver.stat = NULL; }
    if (mode("no-store-open")) { f->store_driver.open = NULL; }
    if (mode("no-store-write")) { f->store_driver.pwrite = NULL; }
    if (mode("no-store-read")) { f->store_driver.pread = NULL; }
    if (mode("no-store-stat")) { f->store_driver.fstat = NULL; }
    if (mode("no-store-truncate")) { f->store_driver.ftruncate = NULL; }
    if (mode("no-store-reserve")) { f->store_driver.reserve = NULL; }
    if (mode("no-store-setattr")) { f->store_driver.setattr = NULL; }
    if (mode("no-store-fsync")) { f->store_driver.fsync = NULL; }
    f->source->driver = &f->source_driver; f->store->driver = &f->store_driver;
}

/* WHAT: Check missing byte primitives. WHY: Optional operations may not dereference NULL.
 * HOW: Invoke the decorated handle and compare the promised refusal. */
static void check_optional(brix_sd_obj_t *object)
{
    char bytes[64]; brix_sd_stat_t status;
    if (mode("no-store-read")) { assert(object->driver->pread(object, bytes, sizeof(bytes), 0) == -1); }
    if (mode("no-store-stat")) { assert(object->driver->fstat(object, &status) == NGX_ERROR); }
    if (mode("no-store-truncate")) {
        assert(object->driver->ftruncate(object, 4) == NGX_ERROR && errno == ENOSYS);
    }
    if (mode("no-store-reserve")) {
        assert(object->driver->reserve(object, 64) == NGX_ERROR && errno == EOPNOTSUPP);
    }
    /* Restore read/metadata capability before asking the mover to consume the spool. */
    state()->store_driver.pread = brix_sd_posix_driver.pread;
    state()->store_driver.fstat = brix_sd_posix_driver.fstat;
    if (mode("reserve")) { assert(object->driver->reserve(object, 64) == NGX_OK); }
}

/* WHAT: Assert a write-open refusal. WHY: The transferred store owner must be released.
 * HOW: Match the injected failure and verify descriptor cleanup for allocation faults. */
static int refused_open(brix_sd_obj_t *object, int error)
{
    int expected = 0;
    if (mode("hydrate-fail")) { expected = EREMOTEIO; }
    if (mode("no-store-open") || mode("no-store-write")) { expected = ENOSYS; }
    if (mode("store-open-error")) { expected = EACCES; }
    if (mode("shell-alloc") || mode("state-alloc")) {
        expected = ENOMEM;
        assert(state()->closed == 1 && fcntl(state()->opened_fd, F_GETFD) == -1 && errno == EBADF);
    }
    if (expected) { assert(object == NULL && error == expected); return 1; }
    return 0;
}

/* WHAT: Check flushing and retry. WHY: A failed transfer must keep the staged bytes.
 * HOW: Write a middle range, assert the durable retry copy and retry once when requested. */
static void write_and_flush(fixture *f, brix_sd_obj_t *object, int sourcefd, int storefd,
                            unsigned char *expected, size_t length)
{
    assert(object->driver->pwrite(object, "new", 3, 8) == 3); memcpy(expected + 8, "new", 3);
    check_bytes(storefd, expected, length);
    if (mode("truncate")) {
        assert(object->driver->ftruncate(object, 16) == NGX_OK); length = 16;
    }
    f->fail_flush = mode("retry");
    ngx_int_t rc = object->driver->fsync(object);
    if (f->fail_flush) {
        assert(rc == NGX_ERROR && errno == EIO); check_bytes(storefd, expected, length);
        f->fail_flush = 0; assert(object->driver->fsync(object) == NGX_OK);
        assert(f->flushes == 2);
    } else { assert(rc == NGX_OK); }
    if (mode("async")) { assert(f->queued == 1 && f->flushes == 0); }
    else { check_bytes(sourcefd, expected, length); }
    unsigned flushes = f->flushes, queued = f->queued;
    assert(object->driver->fsync(object) == NGX_OK && f->flushes == flushes && f->queued == queued);
}

/* WHAT: Select the expected staged contents. WHY: Create and update have different byte ownership.
 * HOW: Preserve the newest full copy, or start with holes for a whole-object create. */
static size_t expected_bytes(unsigned char *expected)
{
    memset(expected, mode("pending") ? 'B' : 'A', 64);
    if (mode("new") || mode("probe-error") || mode("no-source-stat") || mode("trunc-open")) {
        memset(expected, 0, 64); return 11;
    }
    return 64;
}

/* WHAT: Exercise a decorated write handle. WHY: Caller identity and ownership must survive open.
 * HOW: Capture credentials, mutate caller buffers, then run optional and data operations. */
static void check_handle(fixture *f, brix_sd_instance_t *stage, int sourcefd, int storefd)
{
    char principal[32] = "fixture-principal", bearer[32] = "fixture-bearer";
    brix_sd_cred_t cred = {.principal = principal, .bearer = bearer, .fallback_deny = 1};
    int flags = BRIX_SD_O_READ | BRIX_SD_O_WRITE | BRIX_SD_O_CREATE;
    if (mode("trunc-open")) { flags |= BRIX_SD_O_TRUNC; }
    int error = 0;
    brix_sd_obj_t *object = stage->driver->open_cred(stage, "/file", flags, 0600,
                                                    mode("identity") ? &cred : NULL, &error);
    if (refused_open(object, error)) { return; }
    assert(object && object->heap_shell); memset(principal, 'x', 17); memset(bearer, 'y', 14);
    check_optional(object);
    unsigned char expected[64]; size_t length = expected_bytes(expected);
    write_and_flush(f, object, sourcefd, storefd, expected, length);
    int fd = object->fd; assert(object->driver->close(object) == NGX_OK); free(object);
    assert(f->closed >= 1 && fcntl(fd, F_GETFD) == -1 && errno == EBADF);
}

/* WHAT: Run one write-back contract. WHY: Every source and spool path must be owned.
 * HOW: Build borrowed POSIX instances over private roots and clean up all handles. */
int main(int argc, char **argv)
{
    assert(argc == 4); fixture f = {0}; f.mode = argv[1]; f.root = argv[2]; char pointer[64];
    snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_STAGE_WB_FIXTURE", pointer, 1) == 0);
    ngx_log_t log = {0}; ngx_cycle_t cycle = {0}; cycle.log = &log; ngx_cycle = &cycle;
    ngx_os_argv = argv; ngx_time_init(); assert(ngx_os_init(&log) == NGX_OK);
    ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    int sourcefd = open(argv[2], O_RDONLY | O_DIRECTORY), storefd = open(argv[3], O_RDONLY | O_DIRECTORY);
    assert(sourcefd >= 0 && storefd >= 0);
    f.source = brix_sd_posix_borrow_instance(pool, &log, sourcefd, argv[2]);
    f.store = brix_sd_posix_borrow_instance(pool, &log, storefd, argv[3]); assert(f.source && f.store);
    f.store->domain = BRIX_VFS_DOMAIN_STAGE; configure_drivers(&f);
    if (!mode("new")) { seed(sourcefd, 'A'); }
    if (mode("pending") || mode("evict-busy")) { seed(storefd, 'B'); }
    brix_stage_policy_t policy = {0}; policy.flush_mode = mode("async") ? BRIX_WT_MODE_ASYNC : BRIX_WT_MODE_SYNC;
    brix_sd_instance_t *stage = brix_sd_stage_create(f.source, f.store, &policy, argv[2], &log); assert(stage);
    if (!strncmp(f.mode, "evict-", 6)) { check_evict(&f, stage, storefd); }
    else if (!strncmp(f.mode, "namespace-", 10)) { check_namespace(stage); }
    else { check_handle(&f, stage, sourcefd, storefd); }
    brix_sd_stage_destroy(stage); ngx_destroy_pool(pool);
    assert(close(sourcefd) == 0 && close(storefd) == 0);
    assert(unsetenv("BRIX_STAGE_WB_FIXTURE") == 0);
    puts("write-back ownership verified"); return 0;
}
