/* Seed only the explicitly selected empty recovery pool, then remove our keys. */
#include <assert.h>
#include <rados/librados.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
    rados_t cluster;
    rados_ioctx_t io;
    const char *keys[] = {"folder/small", "folder/big", "empty"};
    const size_t lengths[] = {19, 2 * 1024 * 1024 + 7, 0};
    assert(argc == 3);
    assert(rados_create(&cluster, NULL) == 0);
    assert(rados_conf_read_file(cluster, getenv("CEPH_CONF")) == 0);
    assert(rados_connect(cluster) == 0);
    assert(rados_ioctx_create(cluster, argv[1], &io) == 0);
    for (size_t index = 0; index < 3; index++) {
        if (strcmp(argv[2], "clean") == 0) {
            assert(rados_remove(io, keys[index]) == 0);
        } else {
            size_t length = lengths[index];
            char *bytes = malloc(length + 1);
            assert(bytes != NULL);
            for (size_t offset = 0; offset < length; offset++) {
                bytes[offset] = (char) ('A' + offset % 23);
            }
            assert(rados_write_full(io, keys[index], bytes, length) == 0);
            assert(rados_setxattr(io, keys[index], "user.recovery", "fixture", 7) == 0);
            free(bytes);
        }
    }
    rados_ioctx_destroy(io);
    rados_shutdown(cluster);
    return 0;
}
