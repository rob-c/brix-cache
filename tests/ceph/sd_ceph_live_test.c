/*
 * sd_ceph_live_test.c — LIVE standalone test of the sd_ceph driver vtable
 * against a real RADOS pool (tests/ceph_harness.sh).
 *
 * Unlike src/fs/backend/rados/sd_ceph_unittest.c (cluster-free key-map only),
 * this compiles the driver body with BRIX_HAVE_CEPH and drives the vtable
 * directly — open/pwrite/pread/fstat/stat/setxattr/getxattr/listxattr/
 * removexattr/unlink plus the phase-89 namespace plane (mkdir/opendir/
 * readdir/closedir/rename) — proving the librados data + metadata plane
 * end to end,
 * independent of the nginx export wiring.
 *
 * Build (inside the xrd-ceph-build container, where librados-devel exists):
 *   gcc -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src/fs/backend -I src/fs/backend/rados \
 *       -include client/apps/ceph/ngx_shim.h \
 *       tests/ceph/sd_ceph_live_test.c src/fs/backend/rados/sd_ceph.c \
 *       -lrados -o /tmp/sd_ceph_live && /tmp/sd_ceph_live
 *
 * Env: CEPH_POOL (default xrdtest), CEPH_CONF (default /etc/ceph/ceph.conf).
 * Exit 0 = all checks pass.
 */
#include "rados/sd_ceph.h"
#include "sd.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- minimal ngx allocator shims the driver names (no nginx runtime) ------- */
void *ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return calloc(1, size);
}
void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

static int g_fail;
#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) { fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg),       \
                               errno, strerror(errno)); g_fail++; }             \
        else { printf("ok: %s\n", (msg)); }                                     \
    } while (0)

int
main(void)
{
    const brix_sd_driver_t *drv = &brix_sd_ceph_driver;
    brix_sd_instance_t      inst;
    brix_sd_ceph_conf_t     conf;
    brix_sd_obj_t          *o;
    brix_sd_stat_t          stbuf;
    int                       err = 0;
    const char               *path = "/livetest/obj1";
    const char               *payload = "hello rados data plane";
    size_t                    plen = strlen(payload);
    char                      rbuf[256];
    char                      xbuf[256];
    ssize_t                   n;

    memset(&inst, 0, sizeof(inst));
    inst.driver = drv;
    inst.log = NULL;
    inst.pool = NULL;     /* the shims ignore it */
    inst.state = NULL;

    memset(&conf, 0, sizeof(conf));
    conf.conf_file = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    conf.pool = getenv("CEPH_POOL") ? getenv("CEPH_POOL") : "xrdtest";
    conf.key_prefix = "livetest-keys/";   /* isolate from other objects */

    if (drv->init(&inst, &conf) != NGX_OK) {
        fprintf(stderr, "FATAL: sd_ceph init failed (pool=%s conf=%s errno=%d %s)\n",
                conf.pool, conf.conf_file, errno, strerror(errno));
        return 2;
    }
    printf("ok: connected to pool '%s'\n", conf.pool);

    /* clean slate */
    drv->unlink(&inst, path, 0);

    /* --- write path: open(create|write|trunc) → pwrite → fsync → close --- */
    o = drv->open(&inst, path,
                  BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC,
                  0644, &err);
    CHECK(o != NULL, "open for write");
    if (o != NULL) {
        CHECK(drv->pwrite(o, payload, plen, 0) == (ssize_t) plen, "pwrite payload");
        CHECK(drv->fsync(o) == NGX_OK, "fsync");
        CHECK(drv->close(o) == NGX_OK, "close write handle");
    }

    /* --- read path: open(read) → fstat → pread → verify bytes --- */
    err = 0;
    o = drv->open(&inst, path, BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "open for read");
    if (o != NULL) {
        memset(&stbuf, 0, sizeof(stbuf));
        CHECK(drv->fstat(o, &stbuf) == NGX_OK, "fstat");
        CHECK(stbuf.size == (off_t) plen, "fstat size matches");
        memset(rbuf, 0, sizeof(rbuf));
        n = drv->pread(o, rbuf, sizeof(rbuf), 0);
        CHECK(n == (ssize_t) plen, "pread length");
        CHECK(memcmp(rbuf, payload, plen) == 0, "pread bytes match");
        drv->close(o);
    }

    /* --- namespace stat by path --- */
    memset(&stbuf, 0, sizeof(stbuf));
    CHECK(drv->stat(&inst, path, &stbuf) == NGX_OK, "stat by path");
    CHECK(stbuf.size == (off_t) plen, "stat size matches");

    /* --- xattr: set → get → list → remove --- */
    CHECK(drv->setxattr(&inst, path, "user.greeting", "ola", 3, 0) == NGX_OK,
          "setxattr user.greeting");
    memset(xbuf, 0, sizeof(xbuf));
    n = drv->getxattr(&inst, path, "user.greeting", xbuf, sizeof(xbuf));
    CHECK(n == 3 && memcmp(xbuf, "ola", 3) == 0, "getxattr value matches");
    CHECK(drv->getxattr(&inst, path, "user.greeting", NULL, 0) == 3,
          "getxattr size-probe");
    memset(xbuf, 0, sizeof(xbuf));
    n = drv->listxattr(&inst, path, xbuf, sizeof(xbuf));
    CHECK(n > 0, "listxattr non-empty");
    {
        int found = 0; ssize_t i = 0;
        while (i < n) {
            if (strcmp(xbuf + i, "user.greeting") == 0) { found = 1; }
            i += (ssize_t) strlen(xbuf + i) + 1;
        }
        CHECK(found, "listxattr contains user.greeting");
    }
    CHECK(drv->removexattr(&inst, path, "user.greeting") == NGX_OK,
          "removexattr");
    CHECK(drv->getxattr(&inst, path, "user.greeting", xbuf, sizeof(xbuf)) == -1
          && errno == ENODATA, "getxattr after remove is ENODATA");

    /* --- staged write (the WebDAV PUT path): open → write → commit → readback --- */
    {
        const char         *sp = "/livetest/staged1";
        const char         *spay = "staged object payload via staged_*";
        size_t              slen = strlen(spay);
        int                 serr = 0;
        brix_sd_staged_t *sh;

        drv->unlink(&inst, sp, 0);
        sh = drv->staged_open(&inst, sp, 0644, &serr);
        CHECK(sh != NULL, "staged_open");
        if (sh != NULL) {
            CHECK(drv->staged_write(sh, spay, slen, 0) == (ssize_t) slen,
                  "staged_write");
            CHECK(drv->staged_commit(sh, 0) == NGX_OK, "staged_commit");
        }
        o = drv->open(&inst, sp, BRIX_SD_O_READ, 0, &err);
        CHECK(o != NULL, "open staged object for read");
        if (o != NULL) {
            char sb[128];
            memset(sb, 0, sizeof(sb));
            n = drv->pread(o, sb, sizeof(sb), 0);
            CHECK(n == (ssize_t) slen && memcmp(sb, spay, slen) == 0,
                  "staged object bytes match");
            drv->close(o);
        }
        drv->unlink(&inst, sp, 0);
    }

    /* --- phase-89 namespace plane: mkdir / list / rename / rmdir ---
     * success: listing collapses stripes into one file row + one synthetic
     * subdir row; rename lands byte-identical under the new name.
     * error: opendir on an unpopulated prefix is ENOENT; rmdir of a
     * populated synthetic dir is ENOTEMPTY.
     * security-neg: noreplace rename onto an existing object is EEXIST,
     * never a silent clobber. */
    {
        const char       *da = "/livetest/nsdir/a.dat";
        const char       *db = "/livetest/nsdir/sub/b.dat";
        const char       *rn = "/livetest/nsdir/a-renamed.dat";
        brix_sd_dir_t    *d;
        brix_sd_dirent_t  de;
        int               derr = 0, seen_a = 0, seen_sub = 0;

        drv->unlink(&inst, da, 0);
        drv->unlink(&inst, db, 0);
        drv->unlink(&inst, rn, 0);

        CHECK(drv->mkdir(&inst, "/livetest/nsdir", 0755) == NGX_OK,
              "mkdir synthetic no-op");

        o = drv->open(&inst, da,
                      BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC,
                      0644, &err);
        CHECK(o != NULL && drv->pwrite(o, payload, plen, 0) == (ssize_t) plen
              && drv->close(o) == NGX_OK, "create nsdir/a.dat");
        o = drv->open(&inst, db,
                      BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC,
                      0644, &err);
        CHECK(o != NULL && drv->pwrite(o, "b", 1, 0) == 1
              && drv->close(o) == NGX_OK, "create nsdir/sub/b.dat");

        d = drv->opendir(&inst, "/livetest/nsdir", &derr);
        CHECK(d != NULL, "opendir populated dir");
        while (d != NULL && drv->readdir(d, &de) == NGX_OK) {
            if (strcmp(de.name, "a.dat") == 0) { seen_a = 1; }
            if (strcmp(de.name, "sub") == 0)   { seen_sub = 1; }
        }
        if (d != NULL) { drv->closedir(d); }
        CHECK(seen_a && seen_sub,
              "listing collapses stripes: file row + synthetic subdir row");

        derr = 0;
        CHECK(drv->opendir(&inst, "/livetest/no-such-dir", &derr) == NULL
              && derr == ENOENT, "opendir missing dir is ENOENT");

        CHECK(drv->rename(&inst, da, rn, 0) == NGX_OK, "rename copy+delete");
        CHECK(drv->stat(&inst, da, &stbuf) != NGX_OK && errno == ENOENT,
              "rename source gone");
        CHECK(drv->stat(&inst, rn, &stbuf) == NGX_OK
              && stbuf.size == (off_t) plen, "rename dest size matches");

        CHECK(drv->rename(&inst, db, rn, 1) != NGX_OK && errno == EEXIST,
              "rename noreplace onto existing dest is EEXIST");

        CHECK(drv->unlink(&inst, "/livetest/nsdir", 1) != NGX_OK
              && errno == ENOTEMPTY, "rmdir populated synthetic dir is ENOTEMPTY");

        drv->unlink(&inst, rn, 0);
        drv->unlink(&inst, db, 0);
        CHECK(drv->unlink(&inst, "/livetest/nsdir", 1) == NGX_OK,
              "rmdir empty synthetic dir");
    }

    /* --- unlink → stat is ENOENT --- */
    CHECK(drv->unlink(&inst, path, 0) == NGX_OK, "unlink");
    CHECK(drv->stat(&inst, path, &stbuf) != NGX_OK && errno == ENOENT,
          "stat after unlink is ENOENT");

    drv->cleanup(&inst);

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("sd_ceph live driver: all checks passed\n");
    return 0;
}
