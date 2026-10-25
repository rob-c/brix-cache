/*
 * client/lib/platform/linux/preload_lfs.c - the glibc-only entry points
 *
 * WHAT: The LFS *64 spellings (open64, stat64, readdir64, fopen64, ...) and
 *       statx, forwarded to the shim's portable wrappers.
 * WHY:  Tools built with _FILE_OFFSET_BITS=64 (coreutils, python) call the
 *       *64 names, and modern coreutils (ls, stat, find, du) call statx; left
 *       uninterposed they would stat the real (absent) local path and
 *       ENOENT. None of these names exists on Darwin, which is why this
 *       is a host file rather than part of the portable shim.
 * HOW:  Each forwarder calls the wrapper by its libc name, which under
 *       LD_PRELOAD is the shim's own definition. On LP64 glibc the *64
 *       structures are layout-identical to the plain ones (asserted), so the
 *       forward is a cast, not a copy.
 */

#include "platform/preload.h"

#if BRIX_PLATFORM_LINUX

#include "brixposix_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(struct stat) == sizeof(struct stat64),
               "struct stat / stat64 layout differ; *64 stat forwards need rework");
_Static_assert(offsetof(struct stat, st_ino) == offsetof(struct stat64, st_ino)
               && offsetof(struct stat, st_mode) == offsetof(struct stat64, st_mode)
               && offsetof(struct stat, st_size) == offsetof(struct stat64, st_size),
               "struct stat / stat64 member offsets differ");
_Static_assert(sizeof(struct dirent) == sizeof(struct dirent64)
               && offsetof(struct dirent, d_name) == offsetof(struct dirent64, d_name),
               "struct dirent / dirent64 layout differ; readdir64 forward needs rework");

/* WHAT: Return the native LP64 glibc stat structure version.
 * WHY: glibc before 2.33 exports __xstat rather than stat itself.
 * HOW: Prefer the compiling libc's ABI constant; newer headers omit it,
 *      but retain the x86-64 version-1 / other LP64 version-0 ABI. */
static int
preload_stat_version(void)
{
#if defined(_STAT_VER)
    return _STAT_VER;
#elif BRIX_ARCH_X86_64
    return 1;
#else
    return 0;
#endif
}

/* WHAT: Validate the caller's legacy structure version, returning 1 or 0.
 * WHY: An unknown ABI must not receive a differently laid-out struct stat.
 * HOW: Accept only the native layout; otherwise fail with EINVAL. */
static int
preload_stat_version_valid(int version)
{
    if (version != preload_stat_version()) {
        errno = EINVAL;
        return 0;
    }
    return 1;
}

/* WHAT: Invoke the original libc stat without re-entering our wrappers.
 * WHY: Older glibc has no exported stat symbol for RTLD_NEXT to find.
 * HOW: Try modern stat, then the native-version legacy __xstat ABI. */
int
brix_plat_preload_stat(const char *path, struct stat *out)
{
    typedef int (*legacy_fn)(int, const char *, struct stat *);
    __typeof__(stat) *modern = BRIXPOSIX_REAL_RESOLVE(stat);
    legacy_fn legacy;

    if (modern != NULL) {
        return modern(path, out);
    }
    legacy = (legacy_fn) dlsym(RTLD_NEXT, "__xstat");
    if (legacy == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return legacy(preload_stat_version(), path, out);
}

/* WHAT: Invoke original libc lstat on an unmapped path.
 * WHY: Local symlink semantics must survive the old-glibc ABI bridge.
 * HOW: Try lstat, then native-version __lxstat, never the shim itself. */
int
brix_plat_preload_lstat(const char *path, struct stat *out)
{
    typedef int (*legacy_fn)(int, const char *, struct stat *);
    __typeof__(lstat) *modern = BRIXPOSIX_REAL_RESOLVE(lstat);
    legacy_fn legacy;

    if (modern != NULL) {
        return modern(path, out);
    }
    legacy = (legacy_fn) dlsym(RTLD_NEXT, "__lxstat");
    if (legacy == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return legacy(preload_stat_version(), path, out);
}

/* WHAT: Invoke original libc fstat on a real kernel descriptor.
 * WHY: A missing modern libc symbol must not become a NULL call.
 * HOW: Try fstat, then native-version __fxstat, or fail ENOSYS. */
int
brix_plat_preload_fstat(int fd, struct stat *out)
{
    typedef int (*legacy_fn)(int, int, struct stat *);
    __typeof__(fstat) *modern = BRIXPOSIX_REAL_RESOLVE(fstat);
    legacy_fn legacy;

    if (modern != NULL) {
        return modern(fd, out);
    }
    legacy = (legacy_fn) dlsym(RTLD_NEXT, "__fxstat");
    if (legacy == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return legacy(preload_stat_version(), fd, out);
}

/* WHAT: Invoke original libc fstatat, preserving dirfd and flags.
 * WHY: Relative and non-prefix paths remain entirely libc-owned.
 * HOW: Try fstatat, then native-version __fxstatat, or fail ENOSYS. */
int
brix_plat_preload_fstatat(int dirfd, const char *path, struct stat *out, int flags)
{
    typedef int (*legacy_fn)(int, int, const char *, struct stat *, int);
    __typeof__(fstatat) *modern = BRIXPOSIX_REAL_RESOLVE(fstatat);
    legacy_fn legacy;

    if (modern != NULL) {
        return modern(dirfd, path, out, flags);
    }
    legacy = (legacy_fn) dlsym(RTLD_NEXT, "__fxstatat");
    if (legacy == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return legacy(preload_stat_version(), dirfd, path, out, flags);
}

/* WHAT: Interpose legacy path stat, returning the shared wrapper's result.
 * WHY: EL8 coreutils call __xstat directly rather than stat.
 * HOW: Validate the structure ABI before applying the existing path policy. */
int
__xstat(int version, const char *path, struct stat *out)
{
    if (!preload_stat_version_valid(version)) {
        return -1;
    }
    return brixposix_stat_impl(path, out);
}

/* WHAT: Interpose legacy lstat while preserving local symlink behavior.
 * WHY: The versioned ABI must not bypass the configured remote mapping.
 * HOW: Validate the layout, then use the common lstat body. */
int
__lxstat(int version, const char *path, struct stat *out)
{
    if (!preload_stat_version_valid(version)) {
        return -1;
    }
    return brixposix_lstat_impl(path, out);
}

/* WHAT: Interpose legacy descriptor stat, including virtual descriptors.
 * WHY: An unhandled __fxstat sees a shadow descriptor as EBADF.
 * HOW: Validate the layout, then delegate to the existing slot-aware body. */
int
__fxstat(int version, int fd, struct stat *out)
{
    if (!preload_stat_version_valid(version)) {
        return -1;
    }
    return brixposix_fstat_impl(fd, out);
}

/* WHAT: Interpose legacy directory-relative stat.
 * WHY: Old libc's metadata entry point must use the same prefix policy.
 * HOW: Validate the layout, then retain dirfd and flags in the shared body. */
int
__fxstatat(int version, int dirfd, const char *path, struct stat *out, int flags)
{
    if (!preload_stat_version_valid(version)) {
        return -1;
    }
    return brixposix_fstatat_impl(dirfd, path, out, flags);
}

/* WHAT: Forward LP64 legacy large-file stat with its native layout check.
 * WHY: Old _FILE_OFFSET_BITS=64 consumers use the versioned *64 names.
 * HOW: Reuse the matching versioned wrapper; layouts are asserted above. */
int
__xstat64(int version, const char *path, struct stat64 *out)
{
    return __xstat(version, path, (struct stat *) out);
}

/* WHAT: Forward LP64 legacy large-file lstat.
 * WHY: Symlink metadata follows the same compatibility contract as stat.
 * HOW: Delegate to the native-layout versioned lstat wrapper. */
int
__lxstat64(int version, const char *path, struct stat64 *out)
{
    return __lxstat(version, path, (struct stat *) out);
}

/* WHAT: Forward LP64 legacy large-file descriptor stat.
 * WHY: Coreutils using __fxstat64 must recognize shadow descriptors.
 * HOW: Delegate to the same checked versioned fstat body. */
int
__fxstat64(int version, int fd, struct stat64 *out)
{
    return __fxstat(version, fd, (struct stat *) out);
}

/* WHAT: Forward LP64 legacy large-file directory-relative stat.
 * WHY: Both glibc large-file spellings must preserve prefix confinement.
 * HOW: Delegate with the asserted-compatible stat64 layout. */
int
__fxstatat64(int version, int dirfd, const char *path, struct stat64 *out, int flags)
{
    return __fxstatat(version, dirfd, path, (struct stat *) out, flags);
}

static mode_t
open_mode(int flags, va_list ap)
{
    return (flags & O_CREAT) ? (mode_t) va_arg(ap, int) : 0;
}

int
open64(const char *path, int flags, ...)
{
    va_list ap;
    mode_t  mode;

    va_start(ap, flags);
    mode = open_mode(flags, ap);
    va_end(ap);
    return open(path, flags, mode);
}

int
openat64(int dirfd, const char *path, int flags, ...)
{
    va_list ap;
    mode_t  mode;

    va_start(ap, flags);
    mode = open_mode(flags, ap);
    va_end(ap);
    return openat(dirfd, path, flags, mode);
}

ssize_t
pread64(int fd, void *buf, size_t count, off_t offset)
{
    return pread(fd, buf, count, offset); /* vfs-seam-allow: SEAM_CORRECT - LFS forward onto the shim's own wrapper */
}

ssize_t
pwrite64(int fd, const void *buf, size_t count, off_t offset)
{
    return pwrite(fd, buf, count, offset); /* vfs-seam-allow: SEAM_CORRECT - LFS forward onto the shim's own wrapper */
}

off_t
lseek64(int fd, off_t offset, int whence)
{
    return lseek(fd, offset, whence);
}

int
stat64(const char *path, struct stat64 *stbuf)
{
    return brixposix_stat_impl(path, (struct stat *) stbuf);
}

int
lstat64(const char *path, struct stat64 *stbuf)
{
    return brixposix_lstat_impl(path, (struct stat *) stbuf);
}

int
fstat64(int fd, struct stat64 *stbuf)
{
    return brixposix_fstat_impl(fd, (struct stat *) stbuf);
}

int
fstatat64(int dirfd, const char *path, struct stat64 *stbuf, int flags)
{
    return brixposix_fstatat_impl(dirfd, path, (struct stat *) stbuf, flags);
}

struct dirent64 *
readdir64(DIR *dirp)
{
    return (struct dirent64 *) readdir(dirp);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
int
readdir64_r(DIR *dirp, struct dirent64 *entry, struct dirent64 **result)
{
    return readdir_r(dirp, (struct dirent *) entry, (struct dirent **) result);
}
#pragma GCC diagnostic pop

FILE *
fopen64(const char *path, const char *mode)
{
    return fopen(path, mode);
}

FILE *
freopen64(const char *path, const char *mode, FILE *stream)
{
    return freopen(path, mode, stream);
}

/*
 * statx() answers the common fields (type/mode/nlink/size/times/ino) for a
 * remote path from the shim's own stat(), so statx and stat can never
 * disagree; the caller's `mask` is satisfied for what XRootD can report.
 */
int
statx(int dirfd, const char *path, int flags, unsigned int mask,
      struct statx *stxbuf)
{
    char        remote[XRDC_PATH_MAX];
    struct stat mapped;
    REAL(statx);

    if (path[0] != '/' || !map_path(path, remote, sizeof(remote))) {
        return real_statx(dirfd, path, flags, mask, stxbuf);
    }
    if (brixposix_stat_impl(path, &mapped) != 0) {
        return -1;
    }
    memset(stxbuf, 0, sizeof(*stxbuf));
    stxbuf->stx_mask = STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_SIZE
                       | STATX_MTIME | STATX_INO;
    stxbuf->stx_mode    = (uint16_t) mapped.st_mode;
    stxbuf->stx_nlink   = (uint32_t) mapped.st_nlink;
    stxbuf->stx_size    = (uint64_t) mapped.st_size;
    stxbuf->stx_ino     = (uint64_t) mapped.st_ino;
    stxbuf->stx_blksize = (uint32_t) mapped.st_blksize;
    stxbuf->stx_blocks  = (uint64_t) mapped.st_blocks;
    stxbuf->stx_mtime.tv_sec = mapped.st_mtime;
    stxbuf->stx_atime.tv_sec = mapped.st_atime;
    stxbuf->stx_ctime.tv_sec = mapped.st_ctime;
    return 0;
}

#endif /* BRIX_PLATFORM_LINUX */
