/* Native glibc ABI dispatch, real-libc fallback, and bad-version refusal. */
#include "brixposix_internal.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>

#if defined(_STAT_VER)
#define TEST_STAT_VERSION _STAT_VER
#elif BRIX_ARCH_X86_64
#define TEST_STAT_VERSION 1
#else
#define TEST_STAT_VERSION 0
#endif
#define TEST_SHADOW_FD 123456789

extern int __xstat(int, const char *, struct stat *);
extern int __lxstat(int, const char *, struct stat *);
extern int __fxstat(int, int, struct stat *);
extern int __fxstatat(int, int, const char *, struct stat *, int);
extern int __xstat64(int, const char *, struct stat64 *);
extern int __lxstat64(int, const char *, struct stat64 *);
extern int __fxstat64(int, int, struct stat64 *);
extern int __fxstatat64(int, int, const char *, struct stat64 *, int);

static int fixture_stat(struct stat *out)
{
    memset(out, 0, sizeof(*out));
    out->st_mode = S_IFREG | 0644;
    out->st_size = 321;
    return 0;
}

int brixposix_stat_impl(const char *path, struct stat *out)
{
    if (strcmp(path, "/fixture/file") == 0) {
        return fixture_stat(out);
    }
    return brix_plat_preload_stat(path, out);
}

int brixposix_lstat_impl(const char *path, struct stat *out)
{
    if (strcmp(path, "/fixture/file") == 0) {
        return fixture_stat(out);
    }
    return brix_plat_preload_lstat(path, out);
}

int brixposix_fstat_impl(int fd, struct stat *out)
{
    if (fd == TEST_SHADOW_FD) {
        return fixture_stat(out);
    }
    return brix_plat_preload_fstat(fd, out);
}

int brixposix_fstatat_impl(int dirfd, const char *path, struct stat *out, int flags)
{
    if (strcmp(path, "/fixture/file") == 0) {
        return fixture_stat(out);
    }
    return brix_plat_preload_fstatat(dirfd, path, out, flags);
}

int map_path(const char *path, char *out, size_t cap)
{
    (void) path; (void) out; (void) cap;
    return 0;
}

static void success(void)
{
    struct stat value;
    struct stat64 large;
    int ver = TEST_STAT_VERSION;
    assert(__xstat(ver, "/fixture/file", &value) == 0 && value.st_size == 321);
    assert(__lxstat(ver, "/fixture/file", &value) == 0 && value.st_size == 321);
    assert(__fxstat(ver, TEST_SHADOW_FD, &value) == 0 && value.st_size == 321);
    assert(__fxstatat(ver, AT_FDCWD, "/fixture/file", &value, 0) == 0);
    assert(__xstat64(ver, "/fixture/file", &large) == 0 && large.st_size == 321);
    assert(__lxstat64(ver, "/fixture/file", &large) == 0 && large.st_size == 321);
    assert(__fxstat64(ver, TEST_SHADOW_FD, &large) == 0 && large.st_size == 321);
    assert(__fxstatat64(ver, AT_FDCWD, "/fixture/file", &large, 0) == 0);
    assert(stat64("/fixture/file", &large) == 0 && large.st_size == 321);
    assert(fstat64(TEST_SHADOW_FD, &large) == 0 && large.st_size == 321);
}

static void errors(void)
{
    struct stat value;
    assert(__xstat(TEST_STAT_VERSION, "/fixture/no-such-object", &value) == -1);
    assert(errno == ENOENT);
    assert(brix_plat_preload_fstat(-1, &value) == -1 && errno == EBADF);
    assert(brix_plat_preload_fstatat(AT_FDCWD, "/fixture/no-such-object", &value, 0) == -1);
    assert(errno == ENOENT);
}

static void negative(void)
{
    struct stat value, sentinel, local;
    memset(&sentinel, 0x5a, sizeof(sentinel));
    value = sentinel;
    assert(__xstat(INT_MAX, "/fixture/file", &value) == -1 && errno == EINVAL);
    assert(memcmp(&value, &sentinel, sizeof(value)) == 0);
    assert(__fxstat(INT_MAX, TEST_SHADOW_FD, &value) == -1 && errno == EINVAL);
    assert(memcmp(&value, &sentinel, sizeof(value)) == 0);
    assert(__xstat(TEST_STAT_VERSION, "/dev/null", &value) == 0);
    assert(brix_plat_preload_stat("/dev/null", &local) == 0);
    assert(value.st_ino == local.st_ino && value.st_mode == local.st_mode);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    if (strcmp(argv[1], "success") == 0) {
        success();
        return 0;
    }
    if (strcmp(argv[1], "error") == 0) {
        errors();
        return 0;
    }
    assert(strcmp(argv[1], "negative") == 0);
    negative();
    return 0;
}
