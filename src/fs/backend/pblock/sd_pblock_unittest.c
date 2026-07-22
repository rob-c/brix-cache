/*
 * sd_pblock_unittest.c — standalone unit test for the pblock storage driver,
 * driven through the real brix_sd_driver_t vtable function pointers. No nginx,
 * no running server: it builds a throwaway export root under /tmp and exercises
 * every slot plus multi-thread and multi-process concurrency.
 *
 * Build & run (the data plane is real POSIX + SQLite, so it needs libsqlite3 and
 * the ngx-free shim surface in sd.h):
 *   cc -Wall -Wextra -DBRIX_HAVE_SQLITE=1 -DXRDPROTO_NO_NGX -I. \
 *      sd_pblock_unittest.c sd_pblock.c sd_pblock_catalog.c \
 *      -lsqlite3 -lpthread -o /tmp/pb_ut && /tmp/pb_ut
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* nftw(3) + FTW_PHYS for the on-disk block scan */
#endif

#include "fs/backend/sd.h"
#include "sd_pblock_catalog.h"
#include "sd_pblock_unittest_internal.h"

#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>   /* Phase-83 lab tests drive the ctl table directly */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int failures;

const brix_sd_driver_t *D;   /* = &brix_sd_pblock_driver */

/* pb_close — close an object and free its malloc'd shell. driver->close frees the
 * per-open state + fd but not the obj struct (the VFS adopts that by value), so a
 * direct caller owns the shell. */
ngx_int_t
pb_close(brix_sd_obj_t *o)
{
    ngx_int_t rc = D->close(o);

    free(o);
    return rc;
}

/* ---- small helpers over the vtable ---------------------------------------- */

/* write_file — create `path`, write `data`, close. Returns 0 or -1. */
int
write_file(brix_sd_instance_t *inst, const char *path, const char *data,
    size_t len)
{
    int              err = 0;
    brix_sd_obj_t *o;
    ssize_t          n;

    o = D->open(inst, path,
                BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE,
                0644, &err);
    if (o == NULL) {
        return -1;
    }
    n = D->pwrite(o, data, len, 0);
    pb_close(o);
    return (n == (ssize_t) len) ? 0 : -1;
}

/* read_file — open `path` read-only, read up to cap bytes at 0. Returns bytes
 * read or -1. */
ssize_t
read_file(brix_sd_instance_t *inst, const char *path, char *buf, size_t cap)
{
    int              err = 0;
    brix_sd_obj_t *o;
    ssize_t          n;

    o = D->open(inst, path, BRIX_SD_O_READ, 0, &err);
    if (o == NULL) {
        errno = err;
        return -1;
    }
    n = D->pread(o, buf, cap, 0);
    pb_close(o);
    return n;
}

int
main(void)
{
    char                    root[] = "/tmp/pb_ut.XXXXXX";
    brix_sd_pblock_conf_t conf = {0};
    brix_sd_instance_t    inst = {0};

    D = &brix_sd_pblock_driver;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    conf.root = root;
    conf.busy_timeout_ms = 2000;
    conf.block_size = 0;                 /* 0 ⇒ PBLOCK_DEFAULT_BLOCK_SIZE (was
                                          * left uninitialised — stack garbage) */

    inst.driver = D;
    CHECK(D->init(&inst, &conf) == NGX_OK, "init failed: %s", strerror(errno));
    if (failures) { return 1; }

    test_write_read_fstat(&inst);
    test_truncate_and_stat(&inst);
    test_preadv(&inst);
    test_dirs(&inst);
    test_rename(&inst);
    test_server_copy(&inst);
    test_xattr(&inst);
    test_staged(&inst);
    test_unlink(&inst);
    test_threads(&inst);
    test_processes(root, &inst);

    D->cleanup(&inst);
    test_fsync_durability(root);

    test_block_striping();
    test_block_size_configurable();
    test_block_sparse();
    test_block_truncate();
    test_block_copy_and_unlink();
    test_identity();

    /* Phase-83 lab features */
    test_lab_fault_inject();
    test_lab_gate_closed();
    test_lab_caps_mask();
    test_lab_enumerate();
    test_dedup_refs();          /* F10 */
    test_dedup_forged_hash();   /* F10 security-neg */
    test_dedup_gate_closed();   /* F10 gate-off inertness */
    test_snapshot();            /* F6 snapshots take/restore + EBUSY + injection */
    test_versioning();          /* F11 versions trim + trash/undelete + injection */

    if (failures == 0) {
        printf("sd_pblock_unittest: ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "sd_pblock_unittest: %d FAILURE(S)\n", failures);
    return 1;
}
