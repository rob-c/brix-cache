/*
 * striper_to_cephfs.c — SPIKE: migrate one Glasgow/RAL (libradosstriper) file into
 * CephFS WITHOUT moving bytes over the network ("near-in-place").
 *
 * Hypothesis under test: let the MDS own all metadata (create an empty file at the
 * target path with a layout matching the striper geometry → MDS allocates the
 * inode, builds the namespace + backtrace), then re-key the existing striper data
 * objects into the MDS-allocated CephFS object names, then set the size via the
 * MDS. Normal CephFS reads compute object names from (inode, layout, offset) and
 * read straight from RADOS, so they find the re-keyed objects.
 *
 * Only the data-object NAMES move (a within-cluster rados copy), never the file
 * bytes through a client. This avoids the impossible parts (minting inodes /
 * injecting dentries / encoding backtraces) by delegating them to the MDS.
 *
 *   gcc -D_FILE_OFFSET_BITS=64 striper_to_cephfs.c -lcephfs -lrados -o striper_to_cephfs
 *   ./striper_to_cephfs <striper_pool> <soid> <cephfs_data_pool> <cephfs_path>
 *
 * Limitation (spike): stripe_count must be 1 (object index N maps 1:1). Mixed
 * geometries (stripe_count>1, or object_size != CephFS layout) would need the
 * RAID0 index math + a matching CephFS layout.
 */
#include <rados/librados.h>
#include <cephfs/libcephfs.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long
get_xattr_num(rados_ioctx_t io, const char *oid, const char *name, long dflt)
{
    char buf[64];
    int  n = rados_getxattr(io, oid, name, buf, sizeof(buf) - 1);
    if (n <= 0) { return dflt; }
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

/* read an entire RADOS object into a freshly malloc'd buffer; *len set. */
static char *
read_object(rados_ioctx_t io, const char *oid, size_t *len)
{
    uint64_t sz = 0; time_t mt = 0;
    char    *buf;
    int      rc;

    if (rados_stat(io, oid, &sz, &mt) < 0) { return NULL; }
    buf = malloc(sz ? sz : 1);
    rc = rados_read(io, oid, buf, sz, 0);
    if (rc < 0) { free(buf); errno = -rc; return NULL; }
    *len = (size_t) rc;
    return buf;
}

int
main(int argc, char **argv)
{
    rados_t                 cl;
    rados_ioctx_t           sio, dio;
    struct ceph_mount_info *cm;
    const char             *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    const char             *spool, *soid, *dpool, *cpath;
    char                    first[1024], layval[32];
    long                    object_size, stripe_count, total;
    unsigned long long      ino;
    struct ceph_statx       stx;
    long                    i, nobj;
    int                     fd, rc;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <striper_pool> <soid> <cephfs_data_pool> <cephfs_path>\n", argv[0]);
        return 2;
    }
    spool = argv[1]; soid = argv[2]; dpool = argv[3]; cpath = argv[4];

    /* ---- connect RADOS (source striper pool + dest cephfs data pool) ---- */
    if (rados_create(&cl, "admin") < 0 || rados_conf_read_file(cl, conf) < 0
        || rados_connect(cl) < 0) { fprintf(stderr, "rados connect\n"); return 1; }
    if (rados_ioctx_create(cl, spool, &sio) < 0
        || rados_ioctx_create(cl, dpool, &dio) < 0) { fprintf(stderr, "ioctx\n"); return 1; }

    snprintf(first, sizeof(first), "%s.%016x", soid, 0);
    object_size  = get_xattr_num(sio, first, "striper.layout.object_size", 4194304);
    stripe_count = get_xattr_num(sio, first, "striper.layout.stripe_count", 1);
    total        = get_xattr_num(sio, first, "striper.size", -1);
    if (total < 0) { fprintf(stderr, "no striper.size on %s\n", first); return 1; }
    if (stripe_count != 1) { fprintf(stderr, "spike supports stripe_count==1 only (got %ld)\n", stripe_count); return 1; }
    nobj = (total + object_size - 1) / object_size;
    printf("source: object_size=%ld stripe_count=%ld size=%ld -> %ld object(s)\n",
           object_size, stripe_count, total, nobj);

    /* ---- MDS: create the namespace entry with a matching layout ---- */
    if (ceph_create(&cm, "admin") < 0 || ceph_conf_read_file(cm, conf) < 0
        || ceph_mount(cm, "/") < 0) { fprintf(stderr, "cephfs mount\n"); return 1; }

    /* mkdir -p the parent of cpath */
    {
        char dir[1024]; char *slash;
        snprintf(dir, sizeof(dir), "%s", cpath);
        slash = strrchr(dir, '/');
        if (slash && slash != dir) { *slash = '\0'; ceph_mkdirs(cm, dir, 0755); }
    }

    fd = ceph_open(cm, cpath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { fprintf(stderr, "ceph_open %s: %d\n", cpath, fd); return 1; }
    /* set the file layout to match the striper geometry (empty file ⇒ allowed) */
    snprintf(layval, sizeof(layval), "%ld", object_size);
    ceph_fsetxattr(cm, fd, "ceph.file.layout.object_size", layval, strlen(layval), 0);
    ceph_fsetxattr(cm, fd, "ceph.file.layout.stripe_unit", layval, strlen(layval), 0);
    ceph_fsetxattr(cm, fd, "ceph.file.layout.stripe_count", "1", 1, 0);
    ceph_close(cm, fd);

    if (ceph_statx(cm, cpath, &stx, CEPH_STATX_INO, 0) != 0) { fprintf(stderr, "statx\n"); return 1; }
    ino = (unsigned long long) stx.stx_ino;
    printf("MDS allocated inode 0x%llx for %s\n", ino, cpath);

    /* ---- re-key each striper data object into the CephFS object name ---- */
    for (i = 0; i < nobj; i++) {
        char    src[1024], dst[64];
        size_t  len = 0;
        char   *buf;

        snprintf(src, sizeof(src), "%s.%016lx", soid, i);
        snprintf(dst, sizeof(dst), "%llx.%08lx", ino, i);
        buf = read_object(sio, src, &len);
        if (buf == NULL) { fprintf(stderr, "read %s: %s\n", src, strerror(errno)); return 1; }
        rc = rados_write_full(dio, dst, buf, len);
        free(buf);
        if (rc < 0) { fprintf(stderr, "write %s: %s\n", dst, strerror(-rc)); return 1; }
        printf("  re-key %s -> %s (%zu bytes)\n", src, dst, len);
    }

    /* ---- MDS: set the file size to the real total ---- */
    if (ceph_truncate(cm, cpath, total) != 0) { fprintf(stderr, "truncate\n"); return 1; }
    ceph_unmount(cm);
    ceph_release(cm);

    /* ---- verify with a FRESH client (no cached caps) ---- */
    {
        struct ceph_mount_info *vm;
        char                   *rb;
        int                     vfd;
        long                    got = 0;
        ssize_t                 n;

        if (ceph_create(&vm, "admin") < 0 || ceph_conf_read_file(vm, conf) < 0
            || ceph_mount(vm, "/") < 0) { fprintf(stderr, "verify mount\n"); return 1; }
        vfd = ceph_open(vm, cpath, O_RDONLY, 0);
        if (vfd < 0) { fprintf(stderr, "verify open: %d\n", vfd); return 1; }
        rb = malloc(total);
        while (got < total && (n = ceph_read(vm, vfd, rb + got, total - got, got)) > 0) {
            got += n;
        }
        ceph_close(vm, vfd);
        printf("readback: size=%ld head=%.8s tail=%.8s\n",
               got, rb, rb + (got >= 8 ? got - 8 : 0));
        if (got == total && memcmp(rb, "STRIPER0", 8) == 0
            && memcmp(rb + total - 8, "STRIPEND", 8) == 0) {
            printf("RESULT: PASS — CephFS serves the re-keyed striper data\n");
            rc = 0;
        } else {
            printf("RESULT: FAIL — readback mismatch\n");
            rc = 1;
        }
        free(rb);
        ceph_unmount(vm);
        ceph_release(vm);
    }

    rados_ioctx_destroy(sio); rados_ioctx_destroy(dio); rados_shutdown(cl);
    return rc;
}
