/* Exercise the real catalog, block files and optional storage-driver slots. */
#include "fs/backend/sd.h"
#include <assert.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
close_object(brix_sd_obj_t *obj)
{
    assert(obj->inst->driver->close(obj) == NGX_OK);
    free(obj);
}

static brix_sd_obj_t *
open_object(brix_sd_instance_t *inst, const char *path, int flags)
{
    brix_sd_obj_t *obj = inst->driver->open(inst, path, flags, 0600, NULL);
    assert(obj != NULL);
    return obj;
}

static void
publish(brix_sd_instance_t *inst, const char *path, const char *data)
{
    brix_sd_staged_t *sh = inst->driver->staged_open(inst, path, 0600, 0, NULL);
    size_t size = strlen(data);
    assert(sh != NULL);
    assert(inst->driver->staged_write(sh, data, size, 0) == (ssize_t) size);
    assert(inst->driver->staged_commit(sh, NULL) == NGX_OK);
}

static void
read_exact(brix_sd_instance_t *inst, const char *path, const char *expected)
{
    brix_sd_obj_t *obj = open_object(inst, path, BRIX_SD_O_READ);
    char bytes[128] = {0};
    assert(inst->driver->pread(obj, bytes, sizeof(bytes), 0) == (ssize_t) strlen(expected));
    assert(strcmp(bytes, expected) == 0);
    close_object(obj);
}

static void
sql(const char *root, const char *statement)
{
    char path[4096];
    sqlite3 *db = NULL;
    assert(snprintf(path, sizeof(path), "%s/catalog.db", root) > 0);
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_exec(db, statement, NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_close(db) == SQLITE_OK);
}

static void
check_exchange(brix_sd_instance_t *inst)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_stat_t st;
    char value[8] = {0};
    assert(driver->mkdir(inst, "/left", 0700) == NGX_OK);
    assert(driver->mkdir(inst, "/right", 0700) == NGX_OK);
    publish(inst, "/left/a", "left-data");
    publish(inst, "/right/b", "right-data");
    assert(driver->setxattr(inst, "/left/a", "user.tag", "label", 5, 0) == NGX_OK);
    assert(driver->exchange(inst, "/left", "/right") == NGX_OK);
    read_exact(inst, "/right/a", "left-data");
    read_exact(inst, "/left/b", "right-data");
    assert(driver->stat(inst, "/left/a", &st) == NGX_ERROR && errno == ENOENT);
    assert(driver->getxattr(inst, "/right/a", "user.tag", value, sizeof(value)) == 5);
    assert(strcmp(value, "label") == 0);
    assert(driver->exchange(inst, "/left", "/right/a") == NGX_OK);
    read_exact(inst, "/left", "left-data");
    read_exact(inst, "/right/a/b", "right-data");
}

static void
check_bad_exchange(brix_sd_instance_t *inst, const char *kind)
{
    const brix_sd_driver_t *driver = inst->driver;
    const char *a = "/left", *b = "/absent";
    int expected = ENOENT;
    publish(inst, "/left", "original");
    if (strcmp(kind, "same") == 0) { b = "/left"; expected = EINVAL; }
    if (strcmp(kind, "child") == 0) { b = "/left/child"; expected = EINVAL; }
    if (strcmp(kind, "parent") == 0) { a = "/left/child"; b = "/left"; expected = EINVAL; }
    if (strcmp(kind, "first-missing") == 0) { a = "/absent"; b = "/left"; }
    assert(driver->exchange(inst, a, b) == NGX_ERROR && errno == expected);
    read_exact(inst, "/left", "original");
}

static void
check_copy_range(brix_sd_instance_t *inst, size_t size)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_obj_t *src, *dst;
    char *data = malloc(size + 1), *actual = malloc(size + 16);
    size_t offset = 0;
    struct iovec parts[2];
    brix_sd_stat_t st;
    assert(data != NULL && actual != NULL);
    for (size_t i = 0; i < size; i++) { data[i] = (char) ('A' + i % 23); }
    data[size] = 0;
    publish(inst, "/source", data);
    publish(inst, "/dest", "start");
    src = open_object(inst, "/source", BRIX_SD_O_READ);
    dst = open_object(inst, "/dest", BRIX_SD_O_READ | BRIX_SD_O_WRITE);
    while (offset < size) {
        size_t remaining = size - offset;
        ssize_t n = driver->copy_range(src, offset, dst, offset + 5, remaining);
        assert(n == (ssize_t) (remaining < 65536 ? remaining : 65536));
        offset += (size_t) n;
    }
    assert(driver->copy_range(src, size, dst, 0, 10) == 0);
    assert(driver->copy_range(src, 0, dst, 0, 0) == 0);
    assert(driver->fsync(dst) == NGX_OK);
    assert(driver->fstat(dst, &st) == NGX_OK && st.size == (off_t) size + 5);
    parts[0].iov_base = actual; parts[0].iov_len = 5;
    parts[1].iov_base = actual + 5; parts[1].iov_len = size + 1;
    assert(driver->preadv2(dst, parts, 2, 0, 0) == (ssize_t) size + 5);
    assert(memcmp(actual, "start", 5) == 0);
    assert(memcmp(actual + 5, data, size) == 0);
    close_object(src); close_object(dst);
    free(data); free(actual);
}

static void
check_copy_refusal(brix_sd_instance_t *inst, const char *root, const char *kind)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_obj_t *src, *dst;
    int expected = EDQUOT;
    publish(inst, "/source", "12345678");
    publish(inst, "/dest", "old");
    if (strcmp(kind, "lock") == 0) {
        sql(root, "INSERT INTO locks VALUES('/dest',0,8,'W',999,4102444800);");
        expected = EBUSY;
    }
    src = open_object(inst, "/source", BRIX_SD_O_READ);
    dst = open_object(inst, "/dest", BRIX_SD_O_READ | BRIX_SD_O_WRITE);
    assert(driver->copy_range(src, 0, dst, 0, 8) == -1 && errno == expected);
    close_object(src); close_object(dst);
    read_exact(inst, "/dest", "old");
}

static void
check_staged_path(brix_sd_instance_t *inst, size_t size, int encoded)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_staged_t *sh = driver->staged_open(inst, "/staged", 0600, 0, NULL);
    const char *path;
    char *data = calloc(size + 1, 1), *actual = malloc(size + 1);
    assert(sh != NULL && data != NULL && actual != NULL);
    memset(data, 'z', size);
    if (size) { assert(driver->staged_write(sh, data, size, 0) == (ssize_t) size); }
    path = driver->staged_path(sh);
    if (encoded || size > 4096) {
        assert(path == NULL);
    } else {
        int fd;
        assert(path != NULL && strcmp(path, driver->staged_path(sh)) == 0);
        fd = open(path, O_RDONLY);
        assert(fd >= 0 && read(fd, actual, size + 1) == (ssize_t) size);
        assert(memcmp(actual, data, size) == 0);
        close(fd);
    }
    driver->staged_abort(sh);
    free(data); free(actual);
}

static void
check_nearline(brix_sd_instance_t *inst, const char *root, const char *kind)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_residency_t residency;
    char request[40];
    uint64_t bytes = 99;
    publish(inst, "/data", "payload");
    assert(driver->residency(inst, "/data", &residency) == NGX_OK);
    assert(residency == BRIX_SD_RES_ONLINE);
    if (strcmp(kind, "disabled") == 0) {
        assert(driver->evict(inst, "/data", &bytes) == NGX_ERROR && errno == ENOTSUP);
        assert(bytes == 0);
        assert(driver->recall(inst, "/data", request) == NGX_OK && !request[0]);
        return;
    }
    assert(driver->evict(inst, "/data", &bytes) == NGX_OK && bytes == 7);
    assert(driver->evict(inst, "/data", NULL) == NGX_OK);
    assert(driver->residency(inst, "/data", &residency) == NGX_OK);
    assert(residency == BRIX_SD_RES_NEARLINE);
    if (strcmp(kind, "failure") == 0) {
        sql(root, "INSERT INTO ctl(key,value) VALUES('nearline.fail./data','1');");
        assert(driver->recall(inst, "/data", request) == NGX_ERROR && errno == EIO);
        assert(driver->residency(inst, "/data", &residency) == NGX_OK);
        assert(residency == BRIX_SD_RES_LOST);
        assert(driver->evict(inst, "/data", &bytes) == NGX_ERROR && errno == ENOENT);
        assert(bytes == 0);
        return;
    }
    assert(driver->recall(inst, "/data", request) == NGX_OK && !request[0]);
    assert(driver->residency(inst, "/data", &residency) == NGX_OK);
    assert(residency == BRIX_SD_RES_ONLINE);
    read_exact(inst, "/data", "payload");
    assert(driver->recall(inst, "/missing", request) == NGX_ERROR && errno == ENOENT);
    assert(driver->evict(inst, "/missing", &bytes) == NGX_ERROR && errno == ENOENT);
    assert(driver->evict(inst, "/", &bytes) == NGX_ERROR && errno == EISDIR);
}

static void
check_empty_publish_failure(brix_sd_instance_t *inst)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_staged_t *sh;
    char block[4096], *slash;
    const char *path;
    publish(inst, "/protected", "original");
    sh = driver->staged_open(inst, "/protected", 0600, 0, NULL);
    assert(sh != NULL);
    path = driver->staged_path(sh);
    assert(path != NULL);
    assert(snprintf(block, sizeof(block), "%s", path) > 0);
    assert(unlink(block) == 0);
    slash = strrchr(block, '/');
    assert(slash != NULL);
    *slash = 0;
    assert(rmdir(block) == 0);
    assert(driver->staged_commit(sh, NULL) == NGX_ERROR && errno == ENOENT);
    read_exact(inst, "/protected", "original");
    driver->staged_abort(sh);
}

static void
check_identity_exchange(brix_sd_instance_t *inst)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_cred_t owner = {.principal = "owner", .vos = "group"};
    brix_sd_cred_t other = {.principal = "other", .vos = "group"};
    brix_sd_obj_t *obj = driver->open_cred(inst, "/private",
        BRIX_SD_O_READ | BRIX_SD_O_WRITE | BRIX_SD_O_CREATE, 0600, &owner, NULL);
    assert(obj != NULL);
    assert(driver->pwrite(obj, "private", 7, 0) == 7);
    close_object(obj);
    publish(inst, "/service", "service");
    assert(driver->exchange_cred(inst, "/private", "/service", &other) == NGX_ERROR);
    assert(errno == EPERM || errno == EACCES);
    read_exact(inst, "/private", "private");
    read_exact(inst, "/service", "service");
    assert(driver->exchange_cred(inst, "/private", "/service", NULL) == NGX_OK);
    read_exact(inst, "/private", "service");
    read_exact(inst, "/service", "private");
}

static void
check_batch_delete(brix_sd_instance_t *inst, const char *kind)
{
    const brix_sd_driver_t *d = inst->driver;
    const char *paths[] = {"/first", "/absent", "/last"};
    int errors[] = {ECANCELED, ECANCELED, ECANCELED};
    brix_sd_unlink_batch_t batch = {.paths = paths, .errs = errors, .n = 3};
    brix_sd_stat_t st;
    publish(inst, "/first", "one");
    publish(inst, "/last", "two");
    if (!strcmp(kind, "empty")) {
        batch.n = 0; batch.done = 99;
        assert(d->unlink_many(inst, &batch) == NGX_OK && batch.done == 0);
        read_exact(inst, "/first", "one");
        read_exact(inst, "/last", "two");
        return;
    }
    if (!strcmp(kind, "oversized")) {
        batch.n = BRIX_SD_BULK_DELETE_WINDOW + 1;
        assert(d->unlink_many(inst, &batch) == NGX_ERROR && errno == EINVAL);
        assert(batch.done == 0 && errors[0] == ECANCELED);
        read_exact(inst, "/first", "one");
        read_exact(inst, "/last", "two");
        return;
    }
    assert(d->unlink_many_cred(inst, &batch, NULL) == NGX_OK && batch.done == 3);
    assert(errors[0] == 0 && errors[1] == ENOENT && errors[2] == 0);
    assert(d->stat(inst, "/first", &st) == NGX_ERROR && errno == ENOENT);
    assert(d->stat(inst, "/last", &st) == NGX_ERROR && errno == ENOENT);
}

static void
check_batch_identity(brix_sd_instance_t *inst)
{
    const brix_sd_driver_t *d = inst->driver;
    brix_sd_cred_t owner = {.principal = "owner", .vos = "group"};
    brix_sd_cred_t other = {.principal = "other", .vos = "group"};
    const char *paths[] = {"/owned/data", "/foreign/data"};
    int errors[] = {ECANCELED, ECANCELED};
    brix_sd_unlink_batch_t batch = {.paths = paths, .errs = errors, .n = 2};
    brix_sd_stat_t st;
    assert(d->mkdir_cred(inst, "/owned", 0700, &owner) == NGX_OK);
    assert(d->mkdir_cred(inst, "/foreign", 0700, &other) == NGX_OK);
    publish(inst, paths[0], "own");
    publish(inst, paths[1], "protected");
    assert(d->unlink_many_cred(inst, &batch, &owner) == NGX_OK && batch.done == 2);
    assert(errors[0] == 0 && (errors[1] == EACCES || errors[1] == EPERM));
    assert(d->stat(inst, paths[0], &st) == NGX_ERROR && errno == ENOENT);
    read_exact(inst, paths[1], "protected");
}

int
main(int argc, char **argv)
{
    brix_sd_instance_t inst = {0};
    brix_sd_pblock_conf_t conf = {0};
    assert(argc >= 4);
    inst.driver = &brix_sd_pblock_driver;
    inst.caps = inst.driver->caps;
    conf.root = argv[1]; conf.block_size = 4096; conf.busy_timeout_ms = 1000;
    assert(inst.driver->init(&inst, &conf) == NGX_OK);
    if (!strcmp(argv[2], "exchange")) { check_exchange(&inst); }
    else if (!strcmp(argv[2], "bad-exchange")) { check_bad_exchange(&inst, argv[3]); }
    else if (!strcmp(argv[2], "copy")) { check_copy_range(&inst, strtoul(argv[3], NULL, 10)); }
    else if (!strcmp(argv[2], "copy-refusal")) { check_copy_refusal(&inst, argv[1], argv[3]); }
    else if (!strcmp(argv[2], "staged")) { assert(argc == 5); check_staged_path(&inst, strtoul(argv[3], NULL, 10), atoi(argv[4])); }
    else if (!strcmp(argv[2], "nearline")) { check_nearline(&inst, argv[1], argv[3]); }
    else if (!strcmp(argv[2], "identity")) { check_identity_exchange(&inst); }
    else if (!strcmp(argv[2], "empty-failure")) { check_empty_publish_failure(&inst); }
    else if (!strcmp(argv[2], "batch")) { check_batch_delete(&inst, argv[3]); }
    else if (!strcmp(argv[2], "batch-identity")) { check_batch_identity(&inst); }
    else { assert(!"unknown pblock contract"); }
    inst.driver->cleanup(&inst);
    return 0;
}
