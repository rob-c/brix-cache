/* Storage-driver contracts over real RAM objects, reservations and snapshots. */
#include "fs/backend/sd.h"
#include "fs/backend/sd_registry.h"
#include "native_alloc_fail.h"
#include <dirent.h>
#include <limits.h>

static brix_sd_staged_t *
stage(brix_sd_instance_t *inst, const char *name, const char *data)
{
    brix_sd_staged_t *sh;
    int error = 0;
    size_t size = strlen(data);
    sh = inst->driver->staged_open(inst, name, 0600, (off_t) size, &error);
    assert(sh != NULL);
    assert(inst->driver->staged_write(sh, data, size, 0) == (ssize_t) size);
    return sh;
}

static void
publish(brix_sd_instance_t *inst, const char *name, const char *data)
{
    assert(inst->driver->staged_commit(stage(inst, name, data), NULL) == NGX_OK);
}

static void
read_exact(brix_sd_instance_t *inst, const char *path, const char *data)
{
    brix_sd_obj_t *obj = inst->driver->open(inst, path, BRIX_SD_O_READ, 0, NULL);
    char bytes[128] = {0};
    assert(obj != NULL);
    assert(inst->driver->pread(obj, bytes, sizeof(bytes), 0) == (ssize_t) strlen(data));
    assert(strcmp(bytes, data) == 0);
    assert(inst->driver->close(obj) == NGX_OK);
    assert(inst->driver->close(obj) == NGX_OK);
    free(obj);
}

static void
check_data(brix_sd_instance_t *inst)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_obj_t *obj;
    brix_sd_stat_t st;
    brix_sd_space_t space;
    char first[4] = {0}, last[32] = {0};
    struct iovec parts[] = {{first, 3}, {last, sizeof(last)}};
    publish(inst, "/data", "original");
    obj = driver->open(inst, "/data", BRIX_SD_O_READ, 0, NULL);
    assert(obj != NULL && obj->fd == NGX_INVALID_FILE);
    assert(driver->fstat(obj, &st) == NGX_OK && st.size == 8 && st.is_reg);
    assert(driver->preadv(obj, parts, 2, 0) == 8);
    assert(strcmp(first, "ori") == 0 && strcmp(last, "ginal") == 0);
    assert(driver->pread(obj, last, 3, -1) == -1 && errno == EINVAL);
    assert(driver->pread(obj, last, 3, 99) == 0);
    publish(inst, "/data", "replacement");
    assert(driver->pread(obj, last, sizeof(last), 0) == 8);
    assert(memcmp(last, "original", 8) == 0);
    read_exact(inst, "/data", "replacement");
    assert(driver->unlink(inst, "/data", 0) == NGX_OK);
    assert(driver->stat(inst, "/data", &st) == NGX_ERROR && errno == ENOENT);
    assert(driver->space(inst, &space) == NGX_OK && space.used_bytes > 0);
    assert(driver->close(obj) == NGX_OK);
    free(obj);
    assert(driver->space(inst, &space) == NGX_OK && space.used_bytes == 0);
}

static void
check_holes(brix_sd_instance_t *inst)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_staged_t *sh = driver->staged_open(inst, "/hole", 0600, 0, NULL);
    brix_sd_obj_t *obj;
    char data[16];
    assert(sh != NULL);
    assert(driver->staged_write(sh, "end", 3, 7) == 3);
    assert(driver->staged_write(sh, "x", 1, -1) == -1 && errno == EINVAL);
    assert(driver->staged_write(sh, "x", 1, (off_t) SSIZE_MAX) == -1 && errno == EFBIG);
    assert(driver->staged_commit(sh, NULL) == NGX_OK);
    obj = driver->open(inst, "/hole", BRIX_SD_O_READ, 0, NULL);
    assert(obj != NULL);
    memset(data, 0xa5, sizeof(data));
    assert(driver->pread(obj, data, sizeof(data), 0) == 10);
    assert(memcmp(data, "\0\0\0\0\0\0\0end", 10) == 0);
    assert((unsigned char) data[10] == 0xa5);
    assert(driver->close(obj) == NGX_OK);
    free(obj);
}

static void
check_listing(brix_sd_instance_t *inst, const char *path)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_dir_t *dir;
    brix_sd_dirent_t item;
    brix_sd_stat_t st;
    unsigned names = 0;
    assert(driver->mkdir(inst, "/folder", 0700) == NGX_OK);
    assert(driver->mkdir(inst, "/folder", 0700) == NGX_OK);
    assert(driver->stat(inst, "/folder", &st) == NGX_OK && st.is_dir);
    assert(driver->open(inst, "/folder", BRIX_SD_O_READ, 0, NULL) == NULL);
    assert(errno == EISDIR);
    publish(inst, "/folder/one", "1");
    publish(inst, "/folder/nested/two", "2");
    publish(inst, "/folder/nested/three", "3");
    publish(inst, "/folder-other/absent", "4");
    dir = driver->opendir(inst, path, NULL);
    assert(dir != NULL);
    assert(driver->unlink(inst, "/folder/one", 0) == NGX_OK);
    while (driver->readdir(dir, &item) == NGX_OK) {
        if (strcmp(item.name, "one") == 0) {
            assert(item.d_type == DT_REG);
            names |= 1;
        } else {
            assert(strcmp(item.name, "nested") == 0 && item.d_type == DT_DIR);
            names |= 2;
        }
    }
    assert(names == 3);
    assert(driver->readdir(dir, &item) == NGX_DONE);
    assert(driver->closedir(dir) == NGX_OK);
}

static void
check_xattrs(brix_sd_instance_t *inst)
{
    const brix_sd_driver_t *driver = inst->driver;
    char value[32] = {0};
    publish(inst, "/file", "data");
    assert(driver->getxattr(inst, "/file", "user.a", value, 32) == -1 && errno == ENODATA);
    assert(driver->setxattr(inst, "/file", "user.a", "old", 3, 0) == NGX_OK);
    assert(driver->setxattr(inst, "/file", "user.b", "", 0, 0) == NGX_OK);
    assert(driver->getxattr(inst, "/file", "user.a", NULL, 0) == 3);
    assert(driver->getxattr(inst, "/file", "user.a", value, 2) == -1 && errno == ERANGE);
    assert(driver->setxattr(inst, "/file", "user.a", "new", 3, 0) == NGX_OK);
    assert(driver->getxattr(inst, "/file", "user.a", value, 32) == 3);
    assert(memcmp(value, "new", 3) == 0);
    assert(driver->listxattr(inst, "/file", NULL, 0) == 14);
    assert(driver->listxattr(inst, "/file", value, 2) == -1 && errno == ERANGE);
    assert(driver->listxattr(inst, "/file", value, 32) == 14);
    assert(memcmp(value, "user.b\0user.a\0", 14) == 0);
    assert(driver->removexattr(inst, "/file", "user.a") == NGX_OK);
    assert(driver->removexattr(inst, "/file", "absent") == NGX_ERROR && errno == ENODATA);
    assert(driver->removexattr(inst, "/file", "user.b") == NGX_OK);
    assert(driver->listxattr(inst, "/file", value, 32) == 0);
}

static void
check_bad_path(brix_sd_instance_t *inst, const char *path, int expected)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_stat_t st;
    int error = 0;
    assert(driver->stat(inst, path, &st) == NGX_ERROR && errno == expected);
    assert(driver->open(inst, path, BRIX_SD_O_READ, 0, &error) == NULL && error == expected);
    assert(driver->unlink(inst, path, 0) == NGX_ERROR && errno == expected);
    assert(driver->getxattr(inst, path, "user.a", NULL, 0) == -1 && errno == expected);
    assert(driver->listxattr(inst, path, NULL, 0) == -1 && errno == expected);
    assert(driver->setxattr(inst, path, "user.a", "x", 1, 0) == NGX_ERROR && errno == expected);
    assert(driver->removexattr(inst, path, "user.a") == NGX_ERROR && errno == expected);
    if (expected == EINVAL) {
        assert(driver->mkdir(inst, path, 0700) == NGX_ERROR && errno == EINVAL);
        assert(driver->opendir(inst, path, &error) == NULL && error == EINVAL);
        assert(driver->staged_open(inst, path, 0600, 0, &error) == NULL && error == EINVAL);
    }
}

static void
check_precondition(brix_sd_instance_t *inst, const char *mode)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_precond_t pre = {0};
    brix_sd_stat_t st;
    int expected = 0;
    if (strcmp(mode, "missing") != 0 && strcmp(mode, "absent") != 0) {
        publish(inst, "/file", "original");
        assert(driver->stat(inst, "/file", &st) == NGX_OK);
        pre.size = st.size;
        pre.mtime = st.mtime;
    }
    pre.kind = BRIX_SD_PRECOND_MATCH_META;
    if (strcmp(mode, "absent") == 0 || strcmp(mode, "exists") == 0) {
        pre.kind = BRIX_SD_PRECOND_ABSENT;
        expected = strcmp(mode, "exists") == 0 ? EEXIST : 0;
    } else if (strcmp(mode, "missing") == 0) {
        expected = ENOENT;
    } else if (strcmp(mode, "mismatch") == 0) {
        pre.size++;
        expected = ECANCELED;
    } else if (strcmp(mode, "unknown") == 0) {
        pre.kind = 999;
        expected = ENOTSUP;
    }
    assert(driver->staged_commit(stage(inst, "/file", "replacement"), &pre)
           == (expected ? NGX_ERROR : NGX_OK));
    assert(pre.atomic == 1);
    if (expected) { assert(errno == expected); }
    if (strcmp(mode, "missing") != 0) {
        read_exact(inst, "/file", expected ? "original" : "replacement");
    }
}

static void
check_reservations(brix_sd_instance_t *inst)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_staged_t *first, *second;
    brix_sd_space_t space;
    int error;
    assert(driver->staged_open(inst, "/large", 0600, 1048577, &error) == NULL && error == ENOSPC);
    assert(driver->staged_open(inst, "/negative", 0600, -1, &error) == NULL && error == EINVAL);
    first = driver->staged_open(inst, "/a", 0600, 800000, NULL);
    assert(first != NULL);
    assert(driver->space(inst, &space) == NGX_OK && space.used_bytes == 800000);
    assert(driver->staged_open(inst, "/b", 0600, 800000, &error) == NULL && error == ENOSPC);
    driver->staged_abort(first);
    driver->staged_abort(NULL);
    second = driver->staged_open(inst, "/b", 0600, 800000, NULL);
    assert(second != NULL);
    driver->staged_abort(second);
    assert(driver->space(inst, &space) == NGX_OK && space.free_bytes == 1048576);
}

static void
check_failure(brix_sd_instance_t *inst, const char *operation,
    const char *kind, unsigned skip)
{
    const brix_sd_driver_t *driver = inst->driver;
    brix_sd_staged_t *sh = NULL;
    brix_sd_stat_t st;
    int error = 0;
    publish(inst, "/file", "original");
    publish(inst, "/another", "two");
    if (strcmp(operation, "write") == 0) {
        sh = driver->staged_open(inst, "/new", 0600, 0, NULL);
        assert(sh != NULL);
    }
    native_alloc_arm(kind, skip);
    if (strcmp(operation, "open") == 0) {
        assert(driver->open(inst, "/file", BRIX_SD_O_READ, 0, &error) == NULL && error == ENOMEM);
    } else if (strcmp(operation, "staged") == 0) {
        assert(driver->staged_open(inst, "/new", 0600, 1, &error) == NULL && error == ENOMEM);
    } else if (strcmp(operation, "mkdir") == 0) {
        assert(driver->mkdir(inst, "/new", 0700) == NGX_ERROR && errno == ENOMEM);
    } else if (strcmp(operation, "directory") == 0) {
        assert(driver->opendir(inst, "/", &error) == NULL && error == ENOMEM);
    } else if (strcmp(operation, "xattr") == 0) {
        assert(driver->setxattr(inst, "/file", "user.a", "new", 3, 0) == NGX_ERROR && errno == ENOMEM);
    } else {
        assert(sh != NULL);
        assert(driver->staged_write(sh, "new", 3, 0) == -1 && errno == ENOMEM);
    }
    native_alloc_disarm();
    driver->staged_abort(sh);
    assert(driver->stat(inst, "/new", &st) == NGX_ERROR && errno == ENOENT);
    read_exact(inst, "/file", "original");
}

int
main(int argc, char **argv)
{
    ngx_log_t log = {0};
    brix_sd_ram_conf_t conf = {.capacity = 1048576};
    brix_sd_instance_t inst = {.driver = &brix_sd_ram_driver, .log = &log};
    const brix_sd_driver_t *driver = inst.driver;
    assert(argc >= 2);
    if (strcmp(argv[1], "init-failure") == 0) {
        native_alloc_arm("calloc", (unsigned) atoi(argv[2]));
        assert(driver->init(&inst, &conf) == NGX_ERROR && errno == ENOMEM);
        native_alloc_disarm();
        driver->cleanup(&inst);
        return 0;
    }
    if (strcmp(argv[1], "invalid-init") == 0) {
        assert(driver->init(&inst, NULL) == NGX_ERROR && errno == EINVAL);
        conf.capacity = 0;
        assert(driver->init(&inst, &conf) == NGX_ERROR && errno == EINVAL);
        return 0;
    }
    assert(driver->init(&inst, &conf) == NGX_OK);
    if (strcmp(argv[1], "data") == 0) { check_data(&inst); }
    else if (strcmp(argv[1], "holes") == 0) { check_holes(&inst); }
    else if (strcmp(argv[1], "listing") == 0) { check_listing(&inst, argv[2]); }
    else if (strcmp(argv[1], "xattrs") == 0) { check_xattrs(&inst); }
    else if (strcmp(argv[1], "bad-path") == 0) { check_bad_path(&inst, argv[2], EINVAL); }
    else if (strcmp(argv[1], "missing") == 0) { check_bad_path(&inst, "/absent", ENOENT); }
    else if (strcmp(argv[1], "precondition") == 0) { check_precondition(&inst, argv[2]); }
    else if (strcmp(argv[1], "reservations") == 0) { check_reservations(&inst); }
    else if (strcmp(argv[1], "failure") == 0) {
        assert(argc == 5);
        check_failure(&inst, argv[2], argv[3], (unsigned) atoi(argv[4]));
    } else {
        int flags = atoi(argv[2]);
        assert(driver->open(&inst, "/file", flags, 0600, NULL) == NULL && errno == ENOTSUP);
    }
    driver->cleanup(&inst);
    assert(inst.state == NULL);
    driver->cleanup(&inst);
    return 0;
}
