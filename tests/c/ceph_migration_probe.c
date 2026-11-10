/* Independent byte oracle through public CephFS and libradosstriper APIs. */
#include <cephfs/libcephfs.h>
#include <rados/librados.h>
#include <radosstriper/libradosstriper.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
read_cephfs(const char *path, const char *operation)
{
    struct ceph_mount_info *cm = NULL;
    char buffer[65536];
    int fd, count;
    int64_t offset = 0;
    assert(ceph_create(&cm, "admin") == 0);
    assert(ceph_conf_read_file(cm, getenv("CEPH_CONF")) == 0);
    assert(ceph_mount(cm, "/") == 0);
    if (!strcmp(operation, "rmdir")) {
        int rc = ceph_rmdir(cm, path);
        assert(rc == 0 || rc == -ENOENT);
    } else {
        fd = ceph_open(cm, path, O_RDONLY, 0);
        if (!strcmp(operation, "missing")) {
            assert(fd == -ENOENT);
        } else {
            assert(fd >= 0);
            while ((count = ceph_read(cm, fd, buffer, sizeof(buffer), offset)) > 0) {
                assert(fwrite(buffer, 1, count, stdout) == (size_t) count);
                offset += count;
            }
            assert(count == 0 && ceph_close(cm, fd) == 0);
        }
    }
    assert(ceph_unmount(cm) == 0);
    assert(ceph_release(cm) == 0);
}

static void
read_striper(const char *pool, const char *key, const char *operation)
{
    rados_t cluster;
    rados_ioctx_t io;
    rados_striper_t striper;
    char buffer[65536];
    uint64_t offset = 0;
    int count;
    assert(rados_create(&cluster, "admin") == 0);
    assert(rados_conf_read_file(cluster, getenv("CEPH_CONF")) == 0);
    assert(rados_connect(cluster) == 0);
    assert(rados_ioctx_create(cluster, pool, &io) == 0);
    if (!strcmp(operation, "invalid-layout")) {
        assert(rados_setxattr(io, key, "striper.layout.stripe_unit", "3", 1) == 0);
        rados_ioctx_destroy(io);
        rados_shutdown(cluster);
        return;
    }
    if (!strcmp(operation, "remove-object")) {
        assert(rados_remove(io, key) == 0);
        rados_ioctx_destroy(io);
        rados_shutdown(cluster);
        return;
    }
    assert(rados_striper_create(io, &striper) == 0);
    if (!strcmp(operation, "remove")) {
        count = rados_striper_remove(striper, key);
        assert(count == 0 || count == -ENOENT);
    } else if (!strcmp(operation, "missing")) {
        assert(rados_striper_read(striper, key, buffer, 1, 0) == -ENOENT);
    } else {
        while ((count = rados_striper_read(striper, key, buffer, sizeof(buffer), offset)) > 0) {
            assert(fwrite(buffer, 1, count, stdout) == (size_t) count);
            offset += count;
        }
        assert(count == 0);
    }
    rados_striper_destroy(striper);
    rados_ioctx_destroy(io);
    rados_shutdown(cluster);
}

int
main(int argc, char **argv)
{
    assert(argc == 4);
    if (!strcmp(argv[1], "cephfs")) { read_cephfs(argv[2], argv[3]); }
    else { read_striper(argv[1], argv[2], argv[3]); }
    return 0;
}
