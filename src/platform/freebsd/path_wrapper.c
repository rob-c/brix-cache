/* FreeBSD namespace primitives beneath the VFS; shared confinement walk. */
#include "../platform_api.h"
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../posix/path_walk.inc"

/* WHAT: Return native unlink status. WHY: Preserve Linux directory errno.
 * HOW: Normalize only an EPERM response proved to name a directory. */
int
brix_plat_unlinkat(int directory, const char *name, int flags)
{
    struct stat metadata;
    int saved;

    if (unlinkat(directory, name, flags) == 0) { /* vfs-seam-allow: SEAM_CORRECT - native PAL namespace primitive */
        return 0;
    }
    saved = errno;
    if (saved == EPERM && !(flags & AT_REMOVEDIR)
        && fstatat(directory, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 /* vfs-seam-allow: SEAM_CORRECT - normalize native unlink errno */
        && S_ISDIR(metadata.st_mode)) {
        errno = EISDIR;
        return -1;
    }
    errno = saved;
    return -1;
}

/* WHAT: Rename atomically or refuse unsupported flags. WHY: Never emulate an
 * exclusive rename using a racy existence check. HOW: Use native NOREPLACE. */
int
brix_plat_renameat2(int source, const char *name, int destination,
                  const char *new_name, unsigned flags)
{
    if (flags == 0) {
        return renameat(source, name, destination, new_name); /* vfs-seam-allow: SEAM_CORRECT - native PAL namespace primitive */
    }
    if (flags == BRIX_RENAME_NOREPLACE) {
        return renameat2(source, name, destination, new_name, RENAME_NOREPLACE); /* vfs-seam-allow: SEAM_CORRECT - native atomic exclusive rename */
    }
    errno = ENOTSUP;
    return -1;
}

/* WHAT: Return native metadata/birth time. WHY: Handle metadata remains truth.
 * HOW: Stat relative to the supplied directory; publish birth time on success. */
int
brix_plat_fstatat_btime(int directory, const char *name, int flags,
                      struct stat *metadata, time_t *birth)
{
    if (fstatat(directory, name, metadata, flags) != 0) { /* vfs-seam-allow: SEAM_CORRECT - native PAL metadata primitive */
        return -1;
    }
    *birth = metadata->st_birthtim.tv_sec;
    return 0;
}
