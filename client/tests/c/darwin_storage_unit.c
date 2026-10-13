/* Darwin storage success, error, and boundary-integrity contract checks. */
#include "platform/platform.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int
main(void)
{
    char        src_name[] = "/tmp/brix-darwin-src.XXXXXX";
    char        dst_name[] = "/tmp/brix-darwin-dst.XXXXXX";
    const char  source[] = "0123456789";
    char        actual[sizeof(source)] = "----------";
    struct stat before;
    struct stat after;
    off_t       in_off = 2;
    off_t       out_off = 3;
    int         src = mkstemp(src_name);
    int         dst = mkstemp(dst_name);

    assert(src >= 0 && dst >= 0);
    unlink(src_name);
    unlink(dst_name);
    assert(write(src, source, sizeof(source) - 1) == (ssize_t) sizeof(source) - 1);
    assert(write(dst, actual, sizeof(source) - 1) == (ssize_t) sizeof(source) - 1);
    assert(brix_plat_copy_range(src, &in_off, dst, &out_off, 4, 0) == 4);
    assert(in_off == 6 && out_off == 7);
    assert(pread(dst, actual, sizeof(source) - 1, 0) == (ssize_t) sizeof(source) - 1);
    assert(memcmp(actual, "---2345---", sizeof(source) - 1) == 0);

    errno = 0;
    assert(brix_plat_copy_range(src, &in_off, dst, &out_off, 1, 1) == -1);
    assert(errno == EINVAL);
    assert(pread(dst, actual, sizeof(source) - 1, 0) == (ssize_t) sizeof(source) - 1);
    assert(memcmp(actual, "---2345---", sizeof(source) - 1) == 0);

    assert(fstat(dst, &before) == 0);
    assert(brix_plat_reserve(dst, 1024 * 1024) == 0);
    assert(fstat(dst, &after) == 0);
    assert(after.st_size == before.st_size);
    close(src);
    close(dst);
    return 0;
}
