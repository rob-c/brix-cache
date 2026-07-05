/*
 * cephfs_seed.c — create a known CephFS tree via libcephfs (no kernel mount /
 * no /dev/fuse), so the MDS lays down real metadata + data objects we can then
 * dissect on RADOS. Throwaway spike tool.
 *
 *   gcc cephfs_seed.c -lcephfs -o cephfs_seed && ./cephfs_seed
 *   env: CEPH_CONF (default /etc/ceph/ceph.conf)
 */
#include <cephfs/libcephfs.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
put(struct ceph_mount_info *cm, const char *path, const char *data, size_t len)
{
    int fd = ceph_open(cm, path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { fprintf(stderr, "open %s: %d\n", path, fd); return -1; }
    if (ceph_write(cm, fd, data, len, 0) < 0) { fprintf(stderr, "write %s\n", path); }
    ceph_close(cm, fd);
    return 0;
}

int
main(void)
{
    struct ceph_mount_info *cm;
    const char *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    char       *big;
    size_t      biglen = 5u << 20;   /* 5 MiB → spans >1 default 4 MiB object */
    int         rc;

    if ((rc = ceph_create(&cm, "admin")) < 0) { fprintf(stderr, "create %d\n", rc); return 2; }
    if ((rc = ceph_conf_read_file(cm, conf)) < 0) { fprintf(stderr, "conf %d\n", rc); return 2; }
    if ((rc = ceph_mount(cm, "/")) < 0) { fprintf(stderr, "mount %d\n", rc); return 2; }
    printf("mounted cephfs\n");

    ceph_mkdirs(cm, "/dir1/sub", 0755);
    put(cm, "/top.txt", "top-level file\n", 15);
    put(cm, "/dir1/hello.txt", "HELLO CEPHFS via libcephfs\n", 27);

    big = malloc(biglen);
    memset(big, 'Z', biglen);
    memcpy(big, "BIGSTART", 8);
    memcpy(big + biglen - 8, "BIGENDED", 8);
    put(cm, "/dir1/sub/big.bin", big, biglen);
    free(big);

    /* report the inode numbers so we can find the objects */
    {
        struct ceph_statx stx;
        const char *paths[] = { "/", "/top.txt", "/dir1", "/dir1/hello.txt",
                                "/dir1/sub", "/dir1/sub/big.bin" };
        size_t i;
        for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            if (ceph_statx(cm, paths[i], &stx, CEPH_STATX_INO | CEPH_STATX_SIZE, 0) == 0) {
                printf("ino %-12llx size %-10llu  %s\n",
                       (unsigned long long) stx.stx_ino,
                       (unsigned long long) stx.stx_size, paths[i]);
            }
        }
    }
    ceph_unmount(cm);
    ceph_release(cm);
    printf("seed done\n");
    return 0;
}
