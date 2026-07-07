/*
 * sd_cephfs_ro_live_test.c — LIVE test of the read-only CephFS-via-RADOS driver
 * against the seeded CephFS on the demo cluster (cephfs_seed.c + cephfs_seed2.c,
 * after `ceph tell mds.<id> flush journal`). Drives the driver vtable directly
 * (no nginx, no registry): construct an instance, init it on the two pools, then
 * exercise stat / open+pread / opendir+readdir / getxattr / listxattr and verify
 * the known seed values — plus that writes are refused (EROFS).
 *
 *   gcc -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src/fs/backend -I src/fs/backend/rados \
 *     -include client/apps/ceph/ngx_shim.h \
 *     tests/ceph/sd_cephfs_ro_live_test.c src/fs/backend/rados/sd_cephfs_ro.c \
 *     src/fs/backend/rados/sd_ceph.c src/fs/backend/rados/cephfs_layout.c \
 *     src/fs/backend/rados/cephfs_denc.c -lrados -o /tmp/cephfsro_live && /tmp/cephfsro_live
 */
#include "sd.h"
#include "rados/sd_ceph.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* nginx pool allocators the driver names — pool ignored, plain libc here. */
void *ngx_pcalloc(ngx_pool_t *pool, size_t size) { (void) pool; return calloc(1, size); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) { (void) pool; return malloc(size); }

static int failures;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);\
                       failures++; }                                           \
    } while (0)

int
main(void)
{
    const brix_sd_driver_t  *drv = &brix_sd_cephfs_ro_driver;
    brix_sd_instance_t       inst;
    brix_sd_cephfs_ro_conf_t conf;
    brix_sd_stat_t           sb;
    brix_sd_obj_t           *o;
    int                        err = 0;

    memset(&inst, 0, sizeof(inst));
    memset(&conf, 0, sizeof(conf));
    inst.driver = drv;
    conf.meta_pool = getenv("CEPHFS_META") ? getenv("CEPHFS_META") : "cephfs_metadata";
    conf.data_pool = getenv("CEPHFS_DATA") ? getenv("CEPHFS_DATA") : "cephfs_data";
    conf.conf_file = getenv("CEPH_CONF")   ? getenv("CEPH_CONF")   : "/etc/ceph/ceph.conf";

    /* safety gate: init must REFUSE without the quiesce assertion */
    conf.assume_quiesced = 0;
    CHECK(drv->init(&inst, &conf) == NGX_ERROR && errno == EPERM);

    conf.assume_quiesced = 1;
    if (drv->init(&inst, &conf) != NGX_OK) {
        printf("init failed: %s\n", strerror(errno));
        return 1;
    }

    /* stat a known file */
    CHECK(drv->stat(&inst, "/dir1/sub/big.bin", &sb) == NGX_OK);
    CHECK(sb.is_reg && sb.size == 5u * 1024u * 1024u);
    CHECK(drv->stat(&inst, "/dir1/hello.txt", &sb) == NGX_OK && sb.size == 27);
    CHECK(drv->stat(&inst, "/dir1", &sb) == NGX_OK && sb.is_dir);
    CHECK(drv->stat(&inst, "/nope", &sb) == NGX_ERROR && errno == ENOENT);

    /* read the 5 MiB file end to end and check head/tail + total */
    o = drv->open(&inst, "/dir1/sub/big.bin", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL);
    if (o != NULL) {
        char    *buf = malloc(5u << 20);
        size_t   total = 0;
        ssize_t  n;
        while (total < (5u << 20)
               && (n = drv->pread(o, buf + total, (5u << 20) - total,
                                  (off_t) total)) > 0) {
            total += (size_t) n;
        }
        CHECK(total == 5u * 1024u * 1024u);
        CHECK(memcmp(buf, "BIGSTART", 8) == 0);
        CHECK(memcmp(buf + total - 8, "BIGENDED", 8) == 0);
        free(buf);
        drv->close(o);
    }

    /* small file exact contents */
    o = drv->open(&inst, "/dir1/hello.txt", BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL);
    if (o != NULL) {
        char buf[64]; ssize_t n = drv->pread(o, buf, sizeof(buf), 0);
        CHECK(n == 27 && memcmp(buf, "HELLO CEPHFS via libcephfs\n", 27) == 0);
        drv->close(o);
    }

    /* directory listing: /dir1 must contain hello.txt, sub, link */
    {
        brix_sd_dir_t   *d = drv->opendir(&inst, "/dir1", &err);
        brix_sd_dirent_t de;
        int hello = 0, sub = 0, link = 0;
        CHECK(d != NULL);
        if (d != NULL) {
            while (drv->readdir(d, &de) == NGX_OK) {
                if (strcmp(de.name, "hello.txt") == 0) hello = 1;
                if (strcmp(de.name, "sub") == 0)       sub = 1;
                if (strcmp(de.name, "link") == 0)      link = 1;
            }
            drv->closedir(d);
        }
        CHECK(hello && sub && link);
    }

    /* root listing: top.txt + dir1 */
    {
        brix_sd_dir_t   *d = drv->opendir(&inst, "/", &err);
        brix_sd_dirent_t de;
        int top = 0, dir1 = 0;
        CHECK(d != NULL);
        if (d != NULL) {
            while (drv->readdir(d, &de) == NGX_OK) {
                if (strcmp(de.name, "top.txt") == 0) top = 1;
                if (strcmp(de.name, "dir1") == 0)    dir1 = 1;
            }
            drv->closedir(d);
        }
        CHECK(top && dir1);
    }

    /* xattrs on hello.txt */
    {
        char val[64];
        ssize_t n = drv->getxattr(&inst, "/dir1/hello.txt", "user.color",
                                  val, sizeof(val));
        CHECK(n == 4 && memcmp(val, "blue", 4) == 0);
        n = drv->getxattr(&inst, "/dir1/hello.txt", "user.shape", val, sizeof(val));
        CHECK(n == 5 && memcmp(val, "round", 5) == 0);
        n = drv->getxattr(&inst, "/dir1/hello.txt", "user.nope", val, sizeof(val));
        CHECK(n == -1 && errno == ENODATA);
        /* listxattr contains both names */
        {
            char list[256];
            ssize_t L = drv->listxattr(&inst, "/dir1/hello.txt", list, sizeof(list));
            int c = 0, s = 0; ssize_t p = 0;
            CHECK(L > 0);
            while (p < L) {
                if (strcmp(list + p, "user.color") == 0) c = 1;
                if (strcmp(list + p, "user.shape") == 0) s = 1;
                p += (ssize_t) strlen(list + p) + 1;
            }
            CHECK(c && s);
        }
    }

    /* symlink is reported as a symlink by stat */
    CHECK(drv->stat(&inst, "/dir1/link", &sb) == NGX_OK);
    CHECK((sb.mode & 0170000) == 0120000);    /* S_IFLNK */

    /* writes are refused */
    o = drv->open(&inst, "/dir1/new.bin", BRIX_SD_O_WRITE | BRIX_SD_O_CREATE,
                  0644, &err);
    CHECK(o == NULL && err == EROFS);
    CHECK(drv->pwrite == NULL && drv->mkdir == NULL && drv->unlink == NULL
          && drv->rename == NULL && drv->staged_open == NULL);

    drv->cleanup(&inst);

    /* ---- live mode: still-mounted, best-effort with optimistic revalidation -- */
    {
        brix_sd_instance_t       live;
        brix_sd_cephfs_ro_conf_t lconf = conf;

        memset(&live, 0, sizeof(live));
        live.driver = drv;
        lconf.assume_quiesced = 0;
        lconf.live            = 1;
        CHECK(drv->init(&live, &lconf) == NGX_OK);   /* live=1 satisfies the gate */

        /* on a stable fs, revalidation passes and reads return the same data */
        CHECK(drv->stat(&live, "/dir1/sub/big.bin", &sb) == NGX_OK
              && sb.size == 5u * 1024u * 1024u);
        o = drv->open(&live, "/dir1/sub/big.bin", BRIX_SD_O_READ, 0, &err);
        CHECK(o != NULL);
        if (o != NULL) {
            char buf[16];
            CHECK(drv->pread(o, buf, 8, 0) == 8 && memcmp(buf, "BIGSTART", 8) == 0);
            CHECK(drv->pread(o, buf, 8, 5u * 1024u * 1024u - 8) == 8
                  && memcmp(buf, "BIGENDED", 8) == 0);
            drv->close(o);
        }
        {
            brix_sd_dir_t   *d = drv->opendir(&live, "/dir1", &err);
            brix_sd_dirent_t de;
            int hello = 0, sub = 0, link = 0;
            CHECK(d != NULL);
            if (d != NULL) {
                while (drv->readdir(d, &de) == NGX_OK) {
                    if (strcmp(de.name, "hello.txt") == 0) hello = 1;
                    if (strcmp(de.name, "sub") == 0)       sub = 1;
                    if (strcmp(de.name, "link") == 0)      link = 1;
                }
                drv->closedir(d);
            }
            CHECK(hello && sub && link);
        }
        /* genuine, stable not-found still fast-fails (no infinite retry) */
        CHECK(drv->stat(&live, "/nope", &sb) == NGX_ERROR && errno == ENOENT);
        drv->cleanup(&live);
    }

    if (failures == 0) { printf("sd_cephfs_ro_live_test: ALL PASS\n"); return 0; }
    printf("sd_cephfs_ro_live_test: %d FAILURE(S)\n", failures);
    return 1;
}
