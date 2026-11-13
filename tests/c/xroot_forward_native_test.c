/* The child factory is the transport boundary: substitute the actual confined
 * POSIX driver, then exercise the forwarding vtable against real storage. */
#include "fs/backend/xroot/sd_xroot_fwd_internal.h"
#include "fs/backend/sd_registry.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *root;
    unsigned creates, destroys;
    int fail_factory;
} factory_t;

brix_sd_instance_t *
__wrap_brix_sd_xroot_create_origin(const brix_sd_xroot_origin_cfg_t *cfg,
    ngx_log_t *log)
{
    factory_t *factory = log->data;
    factory->creates++;
    assert(!strcmp(cfg->bearer, "test-only-token"));
    assert(!strcmp(cfg->x509_proxy, "/test/proxy"));
    assert(!strcmp(cfg->x509_key, "/test/key"));
    assert(!strcmp(cfg->ca_dir, "/test/ca"));
    assert(!strcmp(cfg->sss_keytab, "/test/sss"));
    assert(cfg->verify_pages && cfg->nearline);
    if (factory->fail_factory) { errno = EHOSTUNREACH; return NULL; }
    brix_sd_instance_t *child = calloc(1, sizeof(*child));
    assert(child != NULL);
    child->driver = &brix_sd_posix_driver;
    child->pool = ngx_create_pool(4096, log); child->log = log;
    assert(child->pool != NULL);
    assert(child->driver->init(child, (void *) factory->root) == NGX_OK);
    child->caps = child->driver->caps;
    return child;
}

void
__wrap_brix_sd_xroot_destroy(brix_sd_instance_t *child)
{
    factory_t *factory = child->log->data;
    factory->destroys++;
    child->driver->cleanup(child);
    ngx_destroy_pool(child->pool);
    free(child);
}

static brix_sd_instance_t *
create(ngx_log_t *log)
{
    char token[] = "test-only-token";
    brix_sd_xroot_fwd_cfg_t config = {.permit = ".example.test",
        .allow_root = 1, .allow_roots = 1,
        .origin = {.bearer = token, .x509_proxy = "/test/proxy",
            .x509_key = "/test/key", .ca_dir = "/test/ca",
            .sss_keytab = "/test/sss", .verify_pages = 1, .nearline = 1}};
    brix_sd_instance_t *instance = brix_sd_xroot_fwd_create(&config, log);
    assert(instance != NULL && brix_sd_xroot_serves(instance));
    assert(instance->caps & BRIX_SD_CAP_NEARLINE);
    memset(token, 'x', sizeof(token) - 1); /* The template must own its copy. */
    return instance;
}

static brix_sd_obj_t *
open_file(brix_sd_instance_t *instance, const char *path)
{
    int error = 0;
    brix_sd_obj_t *object = instance->driver->open(instance, path,
        BRIX_SD_O_READ | BRIX_SD_O_WRITE | BRIX_SD_O_CREATE, 0600, &error);
    assert(object != NULL && error == 0);
    assert(object->inst != instance && object->driver == &brix_sd_posix_driver);
    assert(object->inst->domain == instance->domain);
    return object;
}

static void
io_case(brix_sd_instance_t *instance)
{
    const brix_sd_driver_t *d = instance->driver;
    brix_sd_obj_t *object = open_file(instance, "/root://data.example.test//file");
    char output[8] = {0}; brix_sd_stat_t stat;
    assert(d->pwrite(object, "abcdef", 6, 3) == 6);
    assert(d->fsync(object) == NGX_OK);
    assert(d->fstat(object, &stat) == NGX_OK && stat.size == 9);
    assert(d->pread(object, output, 6, 3) == 6 && !memcmp(output, "abcdef", 6));
    struct iovec vectors[] = {{output, 2}, {output + 2, 4}};
    memset(output, 0, sizeof(output));
    assert(d->preadv(object, vectors, 2, 3) == 6 && !memcmp(output, "abcdef", 6));
    assert(d->ftruncate(object, 4) == NGX_OK);
    assert(d->fstat(object, &stat) == NGX_OK && stat.size == 4);
    assert(d->query_checksum(object, "crc32c", output, sizeof(output)) == NGX_ERROR);
    assert(errno == ENOSYS);
    assert(d->close(object) == NGX_OK);
    int error = 0; brix_sd_open_hints_t hints = {0};
    object = d->open_hinted(instance, "/root://DATA.example.test//file",
                            BRIX_SD_O_READ, 0, NULL, &hints, &error);
    assert(object != NULL && d->close(object) == NGX_OK);
}

static void
directory_contains(brix_sd_instance_t *instance, const char *path,
    const char *name)
{
    int error = 0, found = 0;
    brix_sd_dir_t *dir = instance->driver->opendir(instance, path, &error);
    assert(dir != NULL && error == 0);
    brix_sd_dirent_t entry;
    while (instance->driver->readdir(dir, &entry) == NGX_OK) {
        found |= !strcmp(entry.name, name);
    }
    assert(found && instance->driver->closedir(dir) == NGX_OK);
}

static void
namespace_case(brix_sd_instance_t *instance)
{
    const brix_sd_driver_t *d = instance->driver;
    const char *dir = "/root://data.example.test//dir";
    const char *file = "/root://data.example.test//dir/file";
    const char *copy = "/root://DATA.example.test:1094//dir/copy";
    const char *renamed = "/root://data.example.test//dir/renamed";
    assert(d->mkdir(instance, dir, 0700) == NGX_OK);
    brix_sd_obj_t *object = open_file(instance, file);
    assert(d->pwrite(object, "contents", 8, 0) == 8 && d->close(object) == NGX_OK);
    brix_sd_stat_t stat;
    assert(d->stat(instance, file, &stat) == NGX_OK && stat.size == 8);
    brix_sd_setattr_t attr = {.set_mode = 1, .mode = 0640};
    assert(d->setattr(instance, file, &attr) == NGX_OK);
    assert(d->stat(instance, file, &stat) == NGX_OK && (stat.mode & 0777) == 0640);
    off_t bytes = 0;
    assert(d->server_copy(instance, file, copy, &bytes) == NGX_OK && bytes == 8);
    assert(d->rename(instance, copy, renamed, 1) == NGX_OK);
    directory_contains(instance, dir, "renamed");
    assert(d->unlink(instance, file, 0) == NGX_OK);
    assert(d->unlink(instance, renamed, 0) == NGX_OK);
    assert(d->unlink(instance, dir, 1) == NGX_OK);
    assert(d->stat(instance, file, &stat) == NGX_ERROR && errno == ENOENT);
}

static void
xattr_case(brix_sd_instance_t *instance)
{
    const brix_sd_driver_t *d = instance->driver;
    const char *path = "/root://data.example.test//file";
    brix_sd_obj_t *object = open_file(instance, path);
    assert(d->close(object) == NGX_OK);
    char bytes[1024] = {0};
    assert(d->setxattr(instance, path, "user.forward", "value", 5, 0) == NGX_OK);
    assert(d->getxattr(instance, path, "user.forward", bytes, sizeof(bytes)) == 5);
    assert(!memcmp(bytes, "value", 5));
    memset(bytes, 0, sizeof(bytes));
    ssize_t count = d->listxattr(instance, path, bytes, sizeof(bytes));
    assert(count == sizeof("user.forward") && !strcmp(bytes, "user.forward"));
    assert(d->removexattr(instance, path, "user.forward") == NGX_OK);
    assert(d->getxattr(instance, path, "user.forward", bytes, sizeof(bytes)) == -1);
    assert(errno == ENODATA);
}

static void
stage_case(brix_sd_instance_t *instance, int commit)
{
    const brix_sd_driver_t *d = instance->driver;
    const char *path = "/roots://data.example.test//staged";
    int error = 0;
    brix_sd_staged_t *stage = d->staged_open(instance, path, 0600, 7, &error);
    assert(stage != NULL && error == 0);
    assert(d->staged_write(stage, "payload", 7, 0) == 7);
    brix_sd_stat_t stat;
    assert(d->stat(instance, path, &stat) == NGX_ERROR && errno == ENOENT);
    if (!commit) {
        d->staged_abort(stage);
        assert(d->stat(instance, path, &stat) == NGX_ERROR && errno == ENOENT);
        return;
    }
    brix_sd_precond_t precondition = {.kind = BRIX_SD_PRECOND_ABSENT};
    assert(d->staged_commit(stage, &precondition) == NGX_OK);
    assert(d->stat(instance, path, &stat) == NGX_OK && stat.size == 7);
    brix_sd_obj_t *object = d->open(instance, path, BRIX_SD_O_READ, 0, &error);
    char output[7];
    assert(object != NULL && d->pread(object, output, 7, 0) == 7);
    assert(!memcmp(output, "payload", 7) && d->close(object) == NGX_OK);
}

static void
bad_object(const brix_sd_driver_t *d, brix_sd_obj_t *object)
{
    char bytes[8]; brix_sd_stat_t stat;
    struct iovec vector = {bytes, sizeof(bytes)};
    assert(d->close(object) == NGX_ERROR && errno == ENOSYS);
    assert(d->pread(object, bytes, 8, 0) == -1 && errno == ENOSYS);
    assert(d->pwrite(object, bytes, 8, 0) == -1 && errno == ENOSYS);
    assert(d->preadv(object, &vector, 1, 0) == -1 && errno == ENOSYS);
    assert(d->ftruncate(object, 4) == NGX_ERROR && errno == ENOSYS);
    assert(d->fsync(object) == NGX_ERROR && errno == ENOSYS);
    assert(d->fstat(object, &stat) == NGX_ERROR && errno == ENOSYS);
    assert(d->query_checksum(object, "adler32", bytes, 8) == NGX_ERROR && errno == ENOSYS);
}

static void
bad_handles(brix_sd_instance_t *instance, const char *mode)
{
    brix_sd_driver_t empty = {0};
    const brix_sd_driver_t *d = instance->driver;
    brix_sd_instance_t child = {.driver = &empty};
    if (!strcmp(mode, "null-driver")) { child.driver = NULL; }
    if (!strcmp(mode, "self-driver")) { child.driver = d; }
    brix_sd_obj_t object = {.driver = child.driver, .inst = &child};
    brix_sd_dir_t dir = {.inst = &child};
    brix_sd_staged_t stage = {.inst = &child};
    int null = !strcmp(mode, "null-handles");
    bad_object(d, null ? NULL : &object);
    brix_sd_dirent_t entry;
    assert(d->readdir(null ? NULL : &dir, &entry) == NGX_ERROR && errno == ENOSYS);
    assert(d->closedir(null ? NULL : &dir) == NGX_ERROR && errno == ENOSYS);
    assert(d->staged_write(null ? NULL : &stage, "x", 1, 0) == -1 && errno == ENOSYS);
    assert(d->staged_commit(null ? NULL : &stage, NULL) == NGX_ERROR && errno == ENOSYS);
    d->staged_abort(null ? NULL : &stage);
}

static void
admission(brix_sd_instance_t *instance)
{
    assert(brix_sd_xroot_fwd_admit_key(NULL, "/etc/passwd") == 0);
    assert(brix_sd_xroot_fwd_admit_key(instance, "/etc/passwd") == ENOENT);
    assert(brix_sd_xroot_fwd_admit_key(instance, "/root://other.test//secret") == EACCES);
    assert(brix_sd_xroot_fwd_admit_key(instance, "/roots://a.example.test//file") == 0);
    sd_xroot_fwd_inst_state *state = instance->state;
    assert(state->nchildren == 0);
    state->allow_root = 0;
    assert(brix_sd_xroot_fwd_admit_key(instance, "/root://a.example.test//file") == ENOTSUP);
    state->allow_roots = 0;
    assert(brix_sd_xroot_fwd_admit_key(instance, "/roots://a.example.test//file") == ENOTSUP);
    assert(state->nchildren == 0);
}

static void
origin_cache(brix_sd_instance_t *instance, int capacity)
{
    brix_sd_xroot_fwd_target_t target;
    brix_sd_instance_t *first = sd_xroot_fwd_resolve(instance,
        "/root://a.example.test//file", &target);
    assert(first != NULL && !strcmp(target.path, "/file"));
    assert(sd_xroot_fwd_resolve(instance,
        "/root://A.EXAMPLE.test:1094//other", &target) == first);
    if (!capacity) {
        assert(sd_xroot_fwd_resolve(instance,
            "/roots://a.example.test//file", &target) != first);
        assert(sd_xroot_fwd_resolve(instance,
            "/root://a.example.test:1095//file", &target) != first);
        assert(((sd_xroot_fwd_inst_state *) instance->state)->nchildren == 3);
        return;
    }
    for (unsigned i = 1; i < SD_XROOT_FWD_MAX_CHILDREN; i++) {
        char key[128];
        snprintf(key, sizeof(key), "/root://a.example.test:%u//file", 2000 + i);
        assert(sd_xroot_fwd_resolve(instance, key, &target) != NULL);
    }
    assert(sd_xroot_fwd_resolve(instance, "/root://overflow.example.test//file",
                               &target) == NULL && errno == EMFILE);
    assert(sd_xroot_fwd_resolve(instance, "/root://a.example.test//file", &target) == first);
}

static void
bad_opens(brix_sd_instance_t *instance)
{
    const brix_sd_driver_t *d = instance->driver;
    const char *path = "/root://forbidden.test//secret";
    int error = 0;
    assert(d->open(instance, path, BRIX_SD_O_READ, 0, &error) == NULL && error == EACCES);
    assert(d->open(instance, path, BRIX_SD_O_READ, 0, NULL) == NULL && errno == EACCES);
    assert(d->open_hinted(instance, path, BRIX_SD_O_READ, 0, NULL, NULL,
                          &error) == NULL && error == EACCES);
    assert(d->opendir(instance, path, &error) == NULL && error == EACCES);
    assert(d->staged_open(instance, path, 0600, 1, &error) == NULL && error == EACCES);
}

static void
bad_namespace(brix_sd_instance_t *instance)
{
    const brix_sd_driver_t *d = instance->driver;
    const char *path = "/root://forbidden.test//secret";
    char bytes[64]; brix_sd_stat_t stat; brix_sd_setattr_t attr = {0};
    uint64_t evicted = 0; brix_sd_residency_t residency;
    assert(d->stat(instance, path, &stat) == NGX_ERROR && errno == EACCES);
    assert(d->unlink(instance, path, 0) == NGX_ERROR && errno == EACCES);
    assert(d->mkdir(instance, path, 0600) == NGX_ERROR && errno == EACCES);
    assert(d->setattr(instance, path, &attr) == NGX_ERROR && errno == EACCES);
    assert(d->truncate_path(instance, path, 1) == NGX_ERROR && errno == EACCES);
    assert(d->getxattr(instance, path, "user.x", bytes, 64) == -1 && errno == EACCES);
    assert(d->listxattr(instance, path, bytes, 64) == -1 && errno == EACCES);
    assert(d->setxattr(instance, path, "user.x", "x", 1, 0) == NGX_ERROR && errno == EACCES);
    assert(d->removexattr(instance, path, "user.x") == NGX_ERROR && errno == EACCES);
    assert(d->recall(instance, path, bytes) == NGX_ERROR && errno == EACCES);
    assert(d->residency(instance, path, &residency) == NGX_ERROR && errno == EACCES);
    assert(d->evict(instance, path, &evicted) == NGX_ERROR && errno == EACCES);
}

static void
cross_origin(brix_sd_instance_t *instance)
{
    const brix_sd_driver_t *d = instance->driver;
    const char *source = "/root://a.example.test//file";
    const char *other = "/root://b.example.test//file";
    const char *denied = "/root://forbidden.test//file";
    off_t count = 0;
    assert(d->rename(instance, source, other, 0) == NGX_ERROR && errno == EXDEV);
    assert(d->server_copy(instance, source, other, &count) == NGX_ERROR && errno == EXDEV);
    assert(d->rename(instance, denied, source, 0) == NGX_ERROR && errno == EACCES);
    assert(d->server_copy(instance, source, denied, &count) == NGX_ERROR && errno == EACCES);
}

static void
missing_slots(brix_sd_instance_t *instance)
{
    const brix_sd_driver_t *d = instance->driver;
    const char *path = "/root://a.example.test//file";
    char request_id[40]; uint64_t count = 0; brix_sd_residency_t residency;
    assert(d->recall(instance, path, request_id) == NGX_ERROR && errno == ENOSYS);
    assert(d->residency(instance, path, &residency) == NGX_ERROR && errno == ENOSYS);
    assert(d->evict(instance, path, &count) == NGX_ERROR && errno == ENOSYS);
    assert(d->truncate_path(instance, path, 1) == NGX_ERROR && errno == ENOSYS);
}

static void
invalid_config(ngx_log_t *log)
{
    brix_sd_xroot_fwd_cfg_t config = {0};
    assert(brix_sd_xroot_fwd_create(NULL, log) == NULL && errno == EINVAL);
    assert(brix_sd_xroot_fwd_create(&config, log) == NULL && errno == EINVAL);
    config.permit = ""; config.allow_root = 1;
    assert(brix_sd_xroot_fwd_create(&config, log) == NULL && errno == EINVAL);
    config.permit = ".example.test"; config.allow_root = 0;
    assert(brix_sd_xroot_fwd_create(&config, log) == NULL && errno == EINVAL);
    brix_sd_xroot_fwd_destroy(NULL);
}

static void
dispatch(brix_sd_instance_t *instance, const char *mode)
{
    if (!strcmp(mode, "io")) { io_case(instance); }
    else if (!strcmp(mode, "namespace")) { namespace_case(instance); }
    else if (!strcmp(mode, "xattrs")) { xattr_case(instance); }
    else if (!strncmp(mode, "stage-", 6)) { stage_case(instance, !strcmp(mode, "stage-commit")); }
    else if (!strcmp(mode, "admission")) { admission(instance); }
    else if (!strncmp(mode, "origin-", 7)) { origin_cache(instance, !strcmp(mode, "origin-cap")); }
    else if (!strcmp(mode, "bad-open")) { bad_opens(instance); }
    else if (!strcmp(mode, "bad-namespace")) { bad_namespace(instance); }
    else if (!strcmp(mode, "cross-origin")) { cross_origin(instance); }
    else if (!strcmp(mode, "missing-slots")) { missing_slots(instance); }
    else { bad_handles(instance, mode); }
}

int
main(int argc, char **argv)
{
    assert(argc == 3);
    factory_t factory = {.root = argv[2]};
    ngx_log_t log = {.data = &factory};
    ngx_cycle_t cycle = {.log = &log};
    ngx_cycle = &cycle;
    ngx_time_init(); ngx_os_argv = argv;
    assert(ngx_os_init(&log) == NGX_OK);
    if (!strcmp(argv[1], "invalid-config")) { invalid_config(&log); return 0; }
    brix_sd_instance_t *instance = create(&log);
    if (!strcmp(argv[1], "factory-failure")) {
        factory.fail_factory = 1;
        brix_sd_xroot_fwd_target_t target;
        assert(sd_xroot_fwd_resolve(instance, "/root://a.example.test//file",
                                    &target) == NULL && errno == EHOSTUNREACH);
        assert(factory.creates == 1 && factory.destroys == 0);
        factory.creates = 0;
    } else { dispatch(instance, argv[1]); }
    brix_sd_xroot_fwd_destroy(instance);
    assert(factory.creates == factory.destroys);
    return 0;
}
