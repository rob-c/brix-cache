/*
 * xrdcephfs_rescue.c — offline CephFS recovery tool (operator utility).
 *
 * WHAT: Reads a CephFS directly from its RADOS pools — no kernel mount, no MDS,
 *       no libcephfs — to list, stat, cat, and recursively copy data OUT when the
 *       filesystem cannot be mounted but the pools are intact. It is the
 *       command-line face of the read-only `cephfsro` Storage Driver: it builds a
 *       driver instance and drives the same vtable the nginx export uses, so the
 *       decode/read path is shared and identically tested.
 *
 * SAFETY: like the driver, this assumes a QUIESCED filesystem (MDS down / fs
 *       failed, journal flushed). It only ever reads.
 *
 * USAGE:
 *   xrdcephfs_rescue <meta_pool> <data_pool> ls    <path>
 *   xrdcephfs_rescue <meta_pool> <data_pool> stat  <path>
 *   xrdcephfs_rescue <meta_pool> <data_pool> cat   <path>
 *   xrdcephfs_rescue <meta_pool> <data_pool> get   <path> <local_file>
 *   xrdcephfs_rescue <meta_pool> <data_pool> cp -r <path> <local_dir>
 *   (env CEPH_CONF overrides /etc/ceph/ceph.conf)
 *
 * BUILD: `make -C client ceph-tools` (dep-gated), or by hand where
 * librados-devel exists:
 *   gcc -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src/fs/backend -I src/fs/backend/rados \
 *     -include client/apps/ceph/ngx_shim.h client/apps/ceph/xrdcephfs_rescue.c \
 *     src/fs/backend/rados/sd_cephfs_ro.c src/fs/backend/rados/sd_ceph.c \
 *     src/fs/backend/rados/sd_ceph_compat.c src/fs/backend/rados/cephfs_layout.c \
 *     src/fs/backend/rados/cephfs_denc.c -lrados -o xrdcephfs_rescue
 */
#include "sd.h"
#include "rados/sd_ceph.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

void *ngx_pcalloc(ngx_pool_t *pool, size_t size) { (void) pool; return calloc(1, size); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) { (void) pool; return malloc(size); }

static const brix_sd_driver_t *DRV;
static brix_sd_instance_t      INST;

/* Stream an open object's bytes to a FILE* via the driver's pread. */
static int
copy_to_stream(brix_sd_obj_t *o, FILE *out)
{
    char    buf[1u << 20];
    off_t   off = 0;
    ssize_t n;

    while ((n = DRV->pread(o, buf, sizeof(buf), off)) > 0) {
        if (fwrite(buf, 1, (size_t) n, out) != (size_t) n) { return -1; }
        off += n;
    }
    return (n < 0) ? -1 : 0;
}

static int
do_cat_or_get(const char *path, const char *local)
{
    brix_sd_obj_t *o;
    FILE            *out;
    int              err = 0, rc;

    o = DRV->open(&INST, path, BRIX_SD_O_READ, 0, &err);
    if (o == NULL) { fprintf(stderr, "open %s: %s\n", path, strerror(err)); return 1; }

    out = (local != NULL) ? fopen(local, "wb") : stdout;
    if (out == NULL) { fprintf(stderr, "create %s: %s\n", local, strerror(errno));
                       DRV->close(o); return 1; }

    rc = copy_to_stream(o, out);
    if (local != NULL) { fclose(out); }
    DRV->close(o);
    if (rc != 0) { fprintf(stderr, "read %s failed\n", path); return 1; }
    return 0;
}

static int
do_ls(const char *path)
{
    brix_sd_dir_t   *d;
    brix_sd_dirent_t de;
    int                err = 0;

    d = DRV->opendir(&INST, path, &err);
    if (d == NULL) { fprintf(stderr, "opendir %s: %s\n", path, strerror(err)); return 1; }
    while (DRV->readdir(d, &de) == NGX_OK) {
        printf("%s\n", de.name);
    }
    DRV->closedir(d);
    return 0;
}

static int
do_stat(const char *path)
{
    brix_sd_stat_t sb;

    if (DRV->stat(&INST, path, &sb) != NGX_OK) {
        fprintf(stderr, "stat %s: %s\n", path, strerror(errno));
        return 1;
    }
    printf("path:  %s\n", path);
    printf("type:  %s\n", sb.is_dir ? "dir" : (sb.is_reg ? "file" : "other"));
    printf("size:  %lld\n", (long long) sb.size);
    printf("mode:  0%o\n", (unsigned) sb.mode);
    printf("mtime: %lld\n", (long long) sb.mtime);
    printf("ino:   0x%llx\n", (unsigned long long) sb.ino);
    return 0;
}

/* Recursively copy a CephFS subtree to a local directory. Directories are
 * recreated; regular files are streamed out; other types (symlinks, etc.) are
 * reported and skipped. Returns the number of failures. */
static int
copy_tree(const char *src, const char *dst)
{
    brix_sd_stat_t   sb;
    brix_sd_dir_t   *d;
    brix_sd_dirent_t de;
    int                err = 0, fails = 0;

    if (DRV->stat(&INST, src, &sb) != NGX_OK) {
        fprintf(stderr, "stat %s: %s\n", src, strerror(errno));
        return 1;
    }
    if (sb.is_reg) {
        if (do_cat_or_get(src, dst) != 0) { return 1; }
        printf("  %s -> %s (%lld bytes)\n", src, dst, (long long) sb.size);
        return 0;
    }
    if (!sb.is_dir) {
        fprintf(stderr, "  skip (not a file or dir): %s\n", src);
        return 0;
    }

    if (mkdir(dst, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", dst, strerror(errno));
        return 1;
    }
    d = DRV->opendir(&INST, src, &err);
    if (d == NULL) { fprintf(stderr, "opendir %s: %s\n", src, strerror(err)); return 1; }
    while (DRV->readdir(d, &de) == NGX_OK) {
        char csrc[4096], cdst[4096];
        snprintf(csrc, sizeof(csrc), "%s/%s", src, de.name);
        snprintf(cdst, sizeof(cdst), "%s/%s", dst, de.name);
        fails += copy_tree(csrc, cdst);
    }
    DRV->closedir(d);
    return fails;
}

int
main(int argc, char **argv)
{
    brix_sd_cephfs_ro_conf_t conf;
    const char                *cmd, *path;
    int                        rc;

    if (argc < 5) {
        fprintf(stderr,
            "usage: %s <meta_pool> <data_pool> <ls|stat|cat|get|cp> <path> [args]\n",
            argv[0]);
        return 2;
    }

    DRV = &brix_sd_cephfs_ro_driver;
    memset(&INST, 0, sizeof(INST));
    INST.driver = DRV;

    memset(&conf, 0, sizeof(conf));
    conf.meta_pool       = argv[1];
    conf.data_pool       = argv[2];
    conf.conf_file       = getenv("CEPH_CONF") ? getenv("CEPH_CONF")
                                               : "/etc/ceph/ceph.conf";
    conf.assume_quiesced = 1;   /* the operator runs this against a quiesced fs */

    if (DRV->init(&INST, &conf) != NGX_OK) {
        fprintf(stderr, "connect (meta=%s data=%s): %s\n",
                argv[1], argv[2], strerror(errno));
        return 1;
    }

    cmd = argv[3];
    if (strcmp(cmd, "ls") == 0) {
        rc = do_ls(argv[4]);
    } else if (strcmp(cmd, "stat") == 0) {
        rc = do_stat(argv[4]);
    } else if (strcmp(cmd, "cat") == 0) {
        rc = do_cat_or_get(argv[4], NULL);
    } else if (strcmp(cmd, "get") == 0) {
        if (argc < 6) { fprintf(stderr, "get needs <path> <local_file>\n"); rc = 2; }
        else { rc = do_cat_or_get(argv[4], argv[5]); }
    } else if (strcmp(cmd, "cp") == 0) {
        /* "cp -r <path> <local_dir>" */
        if (argc < 7 || strcmp(argv[4], "-r") != 0) {
            fprintf(stderr, "cp needs: cp -r <path> <local_dir>\n"); rc = 2;
        } else {
            path = argv[5];
            rc = copy_tree(path, argv[6]);
            if (rc == 0) { printf("recovered %s -> %s\n", path, argv[6]); }
        }
    } else {
        fprintf(stderr, "unknown command '%s'\n", cmd);
        rc = 2;
    }

    DRV->cleanup(&INST);
    return rc;
}
