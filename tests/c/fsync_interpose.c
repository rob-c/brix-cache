/* Test-only dyld interposer: retain real object files and the real fsync call.
 * Darwin interposes other images, not the image containing the replacement.
 * Keeping the replacement in a dylib therefore covers the unit executable's
 * production objects while letting its __real_fsync reach libSystem here. */
#include <unistd.h>

int __wrap_fsync(int fd);
int __real_fsync(int fd);

static int
interposed_fsync(int fd)
{
    return __wrap_fsync(fd);
}

int
__real_fsync(int fd)
{
    return fsync(fd);
}

__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } fsync_pair = {
    (const void *) &interposed_fsync, (const void *) &fsync
};
