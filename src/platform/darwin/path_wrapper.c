/*
 * Darwin-only namespace operations beneath the VFS.
 * The host-independent confinement walker is src/platform/posix/path_walk.inc.
 */
#include "../platform.h"
#include "../platform_api.h"
#include <errno.h>
#include <sys/stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../posix/path_walk.inc"

/* Darwin's unlinkat(2) rejects a directory (no AT_REMOVEDIR) with EPERM
 * where Linux answers EISDIR; callers key their "unlink a file, rmdir a
 * directory" fallback on EISDIR, so restore it when the name is a dir. */
int
brix_plat_unlinkat(int dirfd, const char *name, int flags)
{
    struct stat st;
    int         saved;

    if (unlinkat(dirfd, name, flags) == 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL unlink primitive beneath the VFS */
        return 0;
    }
    if (errno != EPERM || (flags & AT_REMOVEDIR)) {
        return -1;
    }
    saved = errno;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 /* vfs-seam-allow: SEAM_CORRECT - PAL unlink primitive beneath the VFS */
        && S_ISDIR(st.st_mode))
    {
        errno = EISDIR;
        return -1;
    }
    errno = saved;
    return -1;
}

int
brix_plat_renameat2(int sfd, const char *sbase, int dfd, const char *dbase,
    unsigned int flags)
{
    unsigned int nflags = 0;

    if (flags & BRIX_RENAME_NOREPLACE) {
        nflags |= RENAME_EXCL;
    }
    if (flags & BRIX_RENAME_EXCHANGE) {
        nflags |= RENAME_SWAP;
    }
    if (renameatx_np(sfd, sbase, dfd, dbase, nflags) == 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL rename primitive beneath the VFS */
        return 0;
    }
    if (errno == ENOTSUP || errno == EINVAL) {
        errno = ENOTSUP;
    }
    return -1;
}

int
brix_plat_fstatat_btime(int dirfd, const char *name, int flags,
    struct stat *st, time_t *btime)
{
    if (fstatat(dirfd, name, st, flags) != 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL metadata primitive beneath the VFS */
        return -1;
    }
    *btime = st->st_birthtimespec.tv_sec;
    return 0;
}
