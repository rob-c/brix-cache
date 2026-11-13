/* Namespace boundaries over real pblock catalogs, bytes and optional side tables. */
#include "fs/backend/pblock/sd_pblock_internal.h"
#include "fs/backend/pblock/sd_pblock_catalog_internal.h"
#include "fs/backend/pblock/pblock_anomaly.h"
#include "fs/backend/pblock/pblock_locks.h"
#include <assert.h>
#include <stdarg.h>

typedef struct { ngx_cycle_t cycle; const char *mode, *root; int armed, synced_fd; } fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return state() && state()->armed && !strcmp(state()->mode, name); }

/* WHAT: Fail the driver-owned durability or directory provider boundary.
 * WHY: A failed barrier or iterator cannot be reported as a completed operation.
 * HOW: Keep real catalog and filesystem work except for the selected failure. */
int __real_open64(const char *, int, ...);
int __wrap_open64(const char *path, int flags, ...)
{
    mode_t permissions = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); permissions = va_arg(args, int); va_end(args); }
    if (mode("sync-open") && !strcmp(path, state()->root)) { errno = EACCES; return -1; }
    int fd = __real_open64(path, flags, permissions);
    if (state() && state()->armed && (flags & O_DIRECTORY)) { state()->synced_fd = fd; }
    return fd;
}
int __real_fsync(int);
int __wrap_fsync(int fd)
{
    if (mode("sync-zero") || mode("sync-error")) { errno = mode("sync-zero") ? 0 : ENOSPC; return -1; }
    return __real_fsync(fd);
}
pblock_catalog_iter *__real_pblock_catalog_opendir(pblock_catalog *, const char *);
pblock_catalog_iter *__wrap_pblock_catalog_opendir(pblock_catalog *cat, const char *path)
{ if (mode("iterator-open")) { errno = EIO; return NULL; } return __real_pblock_catalog_opendir(cat, path); }
int __real_pblock_catalog_readdir(pblock_catalog_iter *, char *, size_t);
int __wrap_pblock_catalog_readdir(pblock_catalog_iter *it, char *name, size_t cap)
{ if (mode("iterator-read")) { errno = EIO; return -1; } return __real_pblock_catalog_readdir(it, name, cap); }

static void publish(brix_sd_instance_t *inst, const char *path, const char *bytes)
{
    brix_sd_staged_t *st = inst->driver->staged_open(inst, path, 0600, 0, NULL); assert(st);
    size_t size = strlen(bytes); assert(inst->driver->staged_write(st, bytes, size, 0) == (ssize_t) size);
    assert(inst->driver->staged_commit(st, NULL) == NGX_OK);
}
static void exact(brix_sd_instance_t *inst, const char *path, const char *bytes)
{
    brix_sd_obj_t *obj = inst->driver->open(inst, path, BRIX_SD_O_READ, 0, NULL); assert(obj);
    char actual[32] = {0}; assert(inst->driver->pread(obj, actual, sizeof(actual), 0) == (ssize_t) strlen(bytes));
    assert(!strcmp(actual, bytes)); brix_sd_obj_release(obj);
}
static void result(ngx_int_t rc, int expected)
{ assert(rc == (expected ? NGX_ERROR : NGX_OK)); if (expected) { assert(errno == expected); } }

/* WHAT: Check namespace refusal before any row or original bytes disappear.
 * WHY: Type, existence, lease and no-replace checks protect existing content.
 * HOW: Exercise plain slots against seeded files and directories. */
static void mutation(brix_sd_instance_t *inst, const char *operation, int expected)
{
    const brix_sd_driver_t *d = inst->driver; pblock_state_t *st = inst->state;
    if (mode("lock-source") || mode("lock-target")) {
        const char *sql = mode("lock-source")
            ? "INSERT INTO locks VALUES('/source',0,0,'X',99,4102444800);"
            : "INSERT INTO locks VALUES('/target',0,0,'X',99,4102444800);";
        assert(!cat_exec(st->cat, sql));
    }
    const char *path = mode("missing") ? "/missing" : "/source";
    if (!strcmp(operation, "rename")) { result(d->rename(inst, path, "/target", mode("noreplace")), expected); }
    else {
        if (mode("directory") || mode("nonempty")) { path = "/dir"; }
        result(d->unlink(inst, path, mode("rmdir-file") || mode("nonempty")), expected);
    }
    if (mode("lock-source") || mode("lock-target")) {
        const char *locked = mode("lock-source") ? "/source" : "/target";
        assert(pblock_locks_ns_check(st, locked, 0) == -1 && errno == EBUSY);
        assert(!cat_exec(st->cat, "DELETE FROM locks;"));
    }
    state()->armed = 0;
    if (expected) { exact(inst, "/source", "source"); exact(inst, "/target", "target"); }
    else if (!strcmp(operation, "rename")) { exact(inst, "/target", "source"); }
    else { brix_sd_stat_t out; assert(d->stat(inst, "/source", &out) == NGX_ERROR && errno == ENOENT); }
}

/* WHAT: Check metadata visibility and transform identity.
 * WHY: A row recorded under another transform must never describe plain bytes.
 * HOW: Change real catalog/control rows and observe the driver stat result. */
static void metadata(brix_sd_instance_t *inst, int expected)
{
    pblock_state_t *st = inst->state; brix_sd_stat_t out;
    if (mode("transform")) {
        pblock_meta meta; assert(!pblock_catalog_lookup(st->cat, "/source", &meta));
        strcpy(meta.xform, "zstd"); assert(!pblock_catalog_put(st->cat, "/source", &meta));
    }
    if (mode("hidden")) {
        assert(!cat_exec(st->cat, "INSERT INTO ctl(key,value) VALUES('anomaly.visibility_ms','60000');"));
        pblock_anomaly_created(st, "/source");
    }
    result(inst->driver->stat(inst, mode("missing") ? "/missing" : "/source", &out), expected);
    if (!expected) { assert(out.size == 6 && (out.mode & 0777) == 0600); }
}

/* WHAT: Iterate real catalog entries and propagate precise setup/read failures.
 * WHY: An unavailable listing must not look like an empty directory.
 * HOW: Check each returned name, list-lag filtering and explicit EOF. */
static void directory(brix_sd_instance_t *inst, int expected)
{
    pblock_state_t *st = inst->state; const brix_sd_driver_t *d = inst->driver;
    const char *path = mode("missing") ? "/missing" : "/dir";
    if (mode("file")) { path = "/source"; }
    if (mode("list-hidden")) {
        assert(!cat_exec(st->cat, "INSERT INTO ctl(key,value) VALUES('anomaly.list_lag_ms','60000');"));
        pblock_anomaly_created(st, "/dir/child");
    }
    int error = 0; brix_sd_dir_t *dir = d->opendir(inst, path, &error);
    if (!dir) { assert(error == expected && expected); return; }
    brix_sd_dirent_t entry; ngx_int_t rc = d->readdir(dir, &entry);
    if (mode("iterator-read")) { result(rc, expected); }
    else if (mode("list-hidden")) { assert(rc == NGX_DONE); }
    else { assert(rc == NGX_OK && !strcmp(entry.name, "child")); assert(d->readdir(dir, &entry) == NGX_DONE); }
    assert(d->closedir(dir) == NGX_OK);
}

/* WHAT: Preserve omitted ownership/times and report exact directory durability.
 * WHY: Optional metadata updates and barriers are externally visible contracts.
 * HOW: Invoke the public driver slots and reread actual catalog metadata. */
static void attributes(brix_sd_instance_t *inst)
{
    brix_sd_setattr_t attr = {.set_times = 1, .set_owner = 1, .set_mode = 1,
        .mode = 0640, .uid = (uid_t) -1, .gid = (gid_t) -1};
    attr.mtime.tv_nsec = mode("omit") ? UTIME_OMIT : UTIME_NOW;
    brix_sd_stat_t before, after;
    assert(inst->driver->stat(inst, "/source", &before) == NGX_OK);
    assert(inst->driver->setattr(inst, "/source", &attr) == NGX_OK);
    assert(inst->driver->stat(inst, "/source", &after) == NGX_OK);
    assert((after.mode & 0777) == 0640 && after.uid == before.uid && after.gid == before.gid);
    if (mode("omit")) { assert(after.mtime == before.mtime); }
    else { assert(after.mtime >= before.mtime); }
}

int main(int argc, char **argv)
{
    assert(argc == 5); fixture f = {0}; f.mode = argv[3]; f.root = argv[1]; f.synced_fd = -1;
    ngx_cycle = &f.cycle; brix_sd_instance_t inst = {.driver = &brix_sd_pblock_driver};
    inst.caps = inst.driver->caps;
    brix_sd_pblock_conf_t conf = {.root = argv[1], .block_size = 4096, .busy_timeout_ms = 1000};
    assert(inst.driver->init(&inst, &conf) == NGX_OK);
    publish(&inst, "/source", "source"); publish(&inst, "/target", "target");
    assert(inst.driver->mkdir(&inst, "/dir", 0700) == NGX_OK); publish(&inst, "/dir/child", "child");
    f.armed = 1; int expected = atoi(argv[4]);
    if (!strcmp(argv[2], "stat")) { metadata(&inst, expected); }
    else if (!strcmp(argv[2], "directory")) { directory(&inst, expected); }
    else if (!strcmp(argv[2], "setattr")) { attributes(&inst); }
    else if (!strcmp(argv[2], "sync")) {
        result(inst.driver->sync_publish(&inst, "/source"), expected);
        if (f.synced_fd >= 0) { assert(fcntl(f.synced_fd, F_GETFD) == -1 && errno == EBADF); }
    } else { mutation(&inst, argv[2], expected); }
    f.armed = 0; inst.driver->cleanup(&inst); ngx_cycle = NULL; return 0;
}
