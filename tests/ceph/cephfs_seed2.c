/*
 * cephfs_seed2.c — augment the seeded CephFS tree with metadata the decoder
 * tests need: user xattrs on a file, and a symlink. Throwaway spike tool (run
 * after cephfs_seed.c, then `ceph tell mds.<id> flush journal`).
 *
 *   gcc -D_FILE_OFFSET_BITS=64 cephfs_seed2.c -lcephfs -o cephfs_seed2 && ./cephfs_seed2
 */
#include <cephfs/libcephfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
    struct ceph_mount_info *cm;
    const char *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    int         rc;

    if ((rc = ceph_create(&cm, "admin")) < 0) { fprintf(stderr, "create %d\n", rc); return 2; }
    if ((rc = ceph_conf_read_file(cm, conf)) < 0) { fprintf(stderr, "conf %d\n", rc); return 2; }
    if ((rc = ceph_mount(cm, "/")) < 0) { fprintf(stderr, "mount %d\n", rc); return 2; }

    /* two user xattrs on hello.txt */
    rc = ceph_setxattr(cm, "/dir1/hello.txt", "user.color", "blue", 4, 0);
    printf("setxattr user.color: %d\n", rc);
    rc = ceph_setxattr(cm, "/dir1/hello.txt", "user.shape", "round", 5, 0);
    printf("setxattr user.shape: %d\n", rc);

    /* a symlink under /dir1 pointing at hello.txt */
    rc = ceph_symlink(cm, "hello.txt", "/dir1/link");
    printf("symlink /dir1/link -> hello.txt: %d\n", rc);

    {
        struct ceph_statx stx;
        if (ceph_statx(cm, "/dir1/link", &stx, CEPH_STATX_INO, AT_SYMLINK_NOFOLLOW) == 0) {
            printf("ino link %llx\n", (unsigned long long) stx.stx_ino);
        }
    }
    ceph_unmount(cm);
    ceph_release(cm);
    printf("seed2 done\n");
    return 0;
}
