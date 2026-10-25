/* Native ELF stat resolution: FreeBSD has no glibc versioned __xstat ABI. */
#include "platform/preload.h"
#include <errno.h>

/* WHAT: Reach original stat. WHY: Non-prefix paths must remain local.
 * HOW: Resolve the next native symbol, refusing unavailable entry points. */
int brix_plat_preload_stat(const char *path, struct stat *output)
{
    __typeof__(stat) *original = BRIXPOSIX_REAL_RESOLVE(stat);
    if (original == NULL) { errno = ENOSYS; return -1; }
    return original(path, output);
}

/* WHAT: Reach original lstat. WHY: Preserve local symlink metadata.
 * HOW: Resolve the native symbol without re-entering the shim. */
int brix_plat_preload_lstat(const char *path, struct stat *output)
{
    __typeof__(lstat) *original = BRIXPOSIX_REAL_RESOLVE(lstat);
    if (original == NULL) { errno = ENOSYS; return -1; }
    return original(path, output);
}

/* WHAT: Reach original fstat. WHY: Real kernel descriptors stay local.
 * HOW: Resolve and invoke the native ABI. */
int brix_plat_preload_fstat(int descriptor, struct stat *output)
{
    __typeof__(fstat) *original = BRIXPOSIX_REAL_RESOLVE(fstat);
    if (original == NULL) { errno = ENOSYS; return -1; }
    return original(descriptor, output);
}

/* WHAT: Reach original directory-relative stat. WHY: Preserve local dirfd scope.
 * HOW: Forward unchanged arguments through the native ABI. */
int brix_plat_preload_fstatat(int directory, const char *path, struct stat *output, int flags)
{
    __typeof__(fstatat) *original = BRIXPOSIX_REAL_RESOLVE(fstatat);
    if (original == NULL) { errno = ENOSYS; return -1; }
    return original(directory, path, output, flags);
}
