/* Catalog scans against the real pblock catalog and bytes; no fake backend. */
#include "fs/scan/scan_engine.h"
#include "protocols/root/protocol/opcodes.h"
#include <assert.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *__real_ngx_alloc(size_t size, ngx_log_t *log);
void *__wrap_ngx_alloc(size_t size, ngx_log_t *log)
{
    if (getenv("BRIX_SCAN_TEST_OOM") != NULL) { errno = ENOMEM; return NULL; }
    return __real_ngx_alloc(size, log);
}

static void
seed(brix_sd_instance_t *inst, unsigned count, int lost)
{
    const brix_sd_driver_t *d = inst->driver;
    assert(d->mkdir(inst, "/nested", 0700) == NGX_OK);
    for (unsigned i = 0; i < count; i++) {
        char name[64], block[4096];
        brix_sd_staged_t *sh;
        snprintf(name, sizeof(name), "/nested/file-%04u\"\\\n", i);
        sh = d->staged_open(inst, name, 0600, 0, NULL);
        assert(sh != NULL);
        assert(d->staged_write(sh, "hello", 5, 0) == 5);
        assert(d->staged_path(sh) != NULL);
        snprintf(block, sizeof(block), "%s", d->staged_path(sh));
        assert(d->staged_commit(sh, NULL) == NGX_OK);
        assert(d->setxattr(inst, name, "user.unchanged", "keep", 4, 0) == NGX_OK);
        if (lost) { assert(unlink(block) == 0); }
    }
}

static void
remove_catalog_table(const char *root)
{
    char path[4096];
    sqlite3 *db = NULL;
    snprintf(path, sizeof(path), "%s/catalog.db", root);
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_exec(db, "DROP TABLE objects", NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_close(db) == SQLITE_OK);
}

static void
check_unchanged(brix_sd_instance_t *inst, unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        char name[64], actual[128] = {0};
        snprintf(name, sizeof(name), "/nested/file-%04u\"\\\n", i);
        assert(inst->driver->getxattr(inst, name, "user.unchanged", actual, sizeof(actual)) == 4);
        assert(memcmp(actual, "keep", 4) == 0);
        assert(inst->driver->getxattr(inst, name, "user.XrdCks.adler32", actual,
                                      sizeof(actual)) == -1);
    }
}

static void
scan(brix_sd_instance_t *inst, const char *mode, const char *kind,
     const char *alg, unsigned count)
{
    brix_scan_opts_t opts = {0};
    brix_scan_summary_t summary = {0};
    u_char *buffer = NULL;
    size_t capacity = 0, used = 0;
    uint16_t error = 0;
    char message[256] = {0};
    ngx_int_t rc;
    int expected = 0;
    snprintf(opts.alg, sizeof(opts.alg), "%s", alg);
    if (!strcmp(kind, "oom")) { assert(setenv("BRIX_SCAN_TEST_OOM", "1", 1) == 0); expected = kXR_NoMemory; }
    if (!strcmp(kind, "unsupported")) { expected = kXR_Unsupported; }
    if (!strcmp(kind, "catalog-error")) { expected = kXR_IOError; }
    if (!strcmp(mode, "inventory")) {
        rc = brix_scan_run_inventory(inst->log, expected == kXR_Unsupported ? NULL : inst,
             &opts, &buffer, &capacity, &used, &summary, &error, message, sizeof(message));
    } else {
        rc = brix_scan_run_verify_catalog(inst->log, expected == kXR_Unsupported ? NULL : inst,
             &opts, &buffer, &capacity, &used, &summary, &error, message, sizeof(message));
    }
    assert(unsetenv("BRIX_SCAN_TEST_OOM") == 0);
    if (expected) {
        assert(rc == NGX_ERROR && error == expected && message[0] != 0);
    } else {
        assert(rc == NGX_OK && summary.files == count);
        if (used) { assert(fwrite(buffer, 1, used, stdout) == used); }
    }
    free(buffer);
    if (strcmp(kind, "catalog-error")) { check_unchanged(inst, count); }
}

int
main(int argc, char **argv)
{
    ngx_log_t log = {0};
    ngx_cycle_t cycle = {.log = &log};
    brix_sd_instance_t inst = {.driver = &brix_sd_pblock_driver, .log = &log};
    brix_sd_pblock_conf_t conf = {0};
    unsigned count;
    assert(argc == 6);
    ngx_cycle = &cycle;
    conf.root = argv[1]; conf.block_size = 4096; conf.busy_timeout_ms = 1000;
    assert(inst.driver->init(&inst, &conf) == NGX_OK);
    count = (unsigned) strtoul(argv[5], NULL, 10);
    seed(&inst, count, !strcmp(argv[3], "lost"));
    if (!strcmp(argv[3], "catalog-error")) { remove_catalog_table(argv[1]); }
    scan(&inst, argv[2], argv[3], argv[4], count);
    inst.driver->cleanup(&inst);
    return 0;
}
