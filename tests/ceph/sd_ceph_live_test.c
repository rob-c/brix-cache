/*
 * sd_ceph_live_test.c — LIVE standalone test of the sd_ceph driver vtable
 * against a real RADOS pool (tests/ceph_harness.sh).
 *
 * Unlike src/fs/backend/rados/sd_ceph_unittest.c (cluster-free key-map only),
 * this compiles the driver body with BRIX_HAVE_CEPH and drives the vtable
 * directly — open/pwrite/pread/fstat/stat/setxattr/getxattr/listxattr/
 * removexattr/unlink plus the phase-89 namespace plane (mkdir/opendir/
 * readdir/closedir/rename), the capacity slot (space) and the two
 * object-metadata slots (setattr over the advisory blob, query_checksum from
 * the OSDs) — proving the librados data + metadata plane end to end,
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
#include <sys/stat.h>

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
        sh = drv->staged_open(&inst, sp, 0644, 0, &serr);
        CHECK(sh != NULL, "staged_open");
        if (sh != NULL) {
            CHECK(drv->staged_write(sh, spay, slen, 0) == (ssize_t) slen,
                  "staged_write");
            CHECK(drv->staged_commit(sh, NULL) == NGX_OK, "staged_commit");
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

    /* --- object metadata: setattr (advisory blob) + query_checksum (OSD) ---
     * Both slots were NULL on this driver before the storage-driver gap wave,
     * and both failed silently: a missing setattr makes chmod a no-op the client
     * is told succeeded, and a missing query_checksum pulls the whole object
     * back across the cluster network to hash bytes the OSDs already hold. */
    {
        brix_sd_setattr_t attr;
        brix_sd_obj_t    *co;
        char              blob[256];
        char              hex[64];
        const char       *ckpath = "/livetest/ckvec";
        /* The published CRC32C check vector. Writing the standard string means
         * the expected digest is a CONSTANT, so this arm proves the OSD's raw
         * running value was seeded and post-conditioned into the canonical
         * crc32c this project speaks — not merely that some 8 hex digits came
         * back. Drop either conditioning step and it reads 0x1cf96d7c. */
        const char       *ckdata = "123456789";
        const char       *ckwant = "e3069283";
        ssize_t           bn;

        /* setattr success: a mode change lands in the advisory blob. RADOS has
         * no POSIX metadata, so the blob IS the observable — there is nothing
         * else for stat to have overlaid. */
        CHECK(drv->setattr != NULL, "setattr slot published");
        memset(&attr, 0, sizeof(attr));
        attr.set_mode = 1;
        attr.mode     = 0640;
        CHECK(drv->setattr(&inst, path, &attr) == NGX_OK, "setattr sets a mode");
        memset(blob, 0, sizeof(blob));
        bn = drv->getxattr(&inst, path, "user.xrd.unixattr", blob,
                           sizeof(blob) - 1);
        CHECK(bn > 0, "setattr persisted an advisory blob");
        CHECK(bn > 0 && strstr(blob, "mode=") != NULL
              && strstr(blob, "640") != NULL,
              "the advisory blob carries the requested mode");

        /* setattr error: a NULL request is EINVAL, and nothing representable is
         * success with NO cluster round trip (an atime-only request). */
        errno = 0;
        CHECK(drv->setattr(&inst, path, NULL) == NGX_ERROR && errno == EINVAL,
              "setattr with a NULL request is EINVAL");
        memset(&attr, 0, sizeof(attr));
        attr.set_times     = 1;
        attr.atime.tv_nsec = UTIME_OMIT;
        attr.mtime.tv_nsec = UTIME_OMIT;
        CHECK(drv->setattr(&inst, path, &attr) == NGX_OK,
              "an unrepresentable setattr succeeds without a write");

        /* setattr security-negative: THE reason the core does a rados_stat when
         * the blob is absent. A setattr on a path that does not exist must not
         * CREATE an object carrying nothing but a mode — stat would thereafter
         * report a file that was never written. */
        memset(&attr, 0, sizeof(attr));
        attr.set_mode = 1;
        attr.mode     = 0600;
        errno = 0;
        CHECK(drv->setattr(&inst, "/livetest/never-written", &attr) == NGX_ERROR
              && errno == ENOENT,
              "setattr on a missing object is ENOENT, not a fabricated object");
        CHECK(drv->stat(&inst, "/livetest/never-written", &stbuf) != NGX_OK
              && errno == ENOENT,
              "and the missing object is still missing afterwards");

        /* query_checksum success: the canonical crc32c of the check vector,
         * computed at the OSDs. */
        CHECK(drv->query_checksum != NULL, "query_checksum slot published");
        drv->unlink(&inst, ckpath, 0);
        err = 0;
        co = drv->open(&inst, ckpath,
                       BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC,
                       0644, &err);
        CHECK(co != NULL, "open the check-vector object for write");
        if (co != NULL) {
            CHECK(drv->pwrite(co, ckdata, strlen(ckdata), 0)
                  == (ssize_t) strlen(ckdata), "write the check vector");
            drv->fsync(co);
            drv->close(co);
        }
        err = 0;
        co = drv->open(&inst, ckpath, BRIX_SD_O_READ, 0, &err);
        CHECK(co != NULL, "open the check-vector object for read");
        if (co != NULL) {
            memset(hex, 0, sizeof(hex));
            CHECK(drv->query_checksum(co, "crc32c", hex, sizeof(hex)) == NGX_OK,
                  "query_checksum answers crc32c from the OSDs");
            CHECK(strcmp(hex, ckwant) == 0,
                  "and the digest is the canonical crc32c check vector");

            /* An algorithm the OSD holds no canonical digest for DECLINES, so
             * the caller recomputes from the bytes. A decline costs one read; a
             * confident wrong digest is presented to the client as fact. */
            memset(hex, 0, sizeof(hex));
            CHECK(drv->query_checksum(co, "adler32", hex, sizeof(hex))
                  == NGX_DECLINED, "an unsupported algorithm declines");
            CHECK(hex[0] == '\0', "and writes no digest at all");
            CHECK(drv->query_checksum(co, "crc32", hex, sizeof(hex))
                  == NGX_DECLINED,
                  "crc32 is not crc32c on a prefix match either");

            /* Security-negative: a buffer too small for 8 hex digits and a NUL
             * declines rather than truncating a digest into a shorter, wrong
             * one that still looks well formed. */
            memset(hex, 0, sizeof(hex));
            CHECK(drv->query_checksum(co, "crc32c", hex, 8) == NGX_DECLINED,
                  "a short buffer declines rather than truncating a digest");
            CHECK(hex[0] == '\0', "and leaves the caller's buffer untouched");
            CHECK(drv->query_checksum(co, NULL, hex, sizeof(hex))
                  == NGX_DECLINED, "a NULL algorithm declines");
            drv->close(co);
        }

        /* An empty object is the identity CRC32C, not an error and not a
         * decline: the OSD returns nothing to interpret for a zero-length
         * range, so the slot answers the value directly. */
        drv->unlink(&inst, ckpath, 0);
        err = 0;
        co = drv->open(&inst, ckpath,
                       BRIX_SD_O_WRITE | BRIX_SD_O_CREATE, 0644, &err);
        if (co != NULL) {
            drv->pwrite(co, "", 0, 0);
            drv->close(co);
        }
        err = 0;
        co = drv->open(&inst, ckpath, BRIX_SD_O_READ, 0, &err);
        if (co != NULL) {
            memset(hex, 0, sizeof(hex));
            CHECK(drv->query_checksum(co, "crc32c", hex, sizeof(hex)) == NGX_OK
                  && strcmp(hex, "00000000") == 0,
                  "a zero-length object checksums to the identity value");
            drv->close(co);
        }
        drv->unlink(&inst, ckpath, 0);
    }

    /* --- unlink → stat is ENOENT --- */
    CHECK(drv->unlink(&inst, path, 0) == NGX_OK, "unlink");
    CHECK(drv->stat(&inst, path, &stbuf) != NGX_OK && errno == ENOENT,
          "stat after unlink is ENOENT");

    /* --- capacity (kXR_Qspace / QFSinfo) ---
     * success: the slot answers the CLUSTER's figures, and the triple is
     * self-consistent (a used+free that exceeds total means the driver mixed a
     * pool's logical bytes into a raw total).
     * security-neg: a NULL out is EINVAL, never a write through the pointer —
     * the seam calls this on a path the client controls the timing of. */
    {
        brix_sd_space_t sp;

        CHECK(drv->space != NULL, "space slot published");
        memset(&sp, 0, sizeof(sp));
        CHECK(drv->space(&inst, &sp) == NGX_OK, "space on the live cluster");
        CHECK(sp.total_bytes > 0, "space total is non-zero");
        CHECK(sp.used_bytes + sp.free_bytes <= sp.total_bytes,
              "space used+free fits inside total");
        CHECK(sp.free_bytes <= sp.total_bytes, "space free fits inside total");

        errno = 0;
        CHECK(drv->space(&inst, NULL) == NGX_ERROR && errno == EINVAL,
              "space with NULL out is EINVAL");

        drv->cleanup(&inst);

        /* error: after cleanup there is no cluster handle — ENOTCONN, never a
         * use-after-shutdown call into librados. */
        errno = 0;
        CHECK(drv->space(&inst, &sp) == NGX_ERROR && errno == ENOTCONN,
              "space on a torn-down instance is ENOTCONN");
    }

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("sd_ceph live driver: all checks passed\n");
    return 0;
}
