/*
 * src/platform/linux/path_wrapper.c - Linux path primitives beneath the VFS seam
 *
 * WHAT: openat2(2), the confined stat, renameat2(2) and the statx birth time
 *       declared in platform_api_posix.h.
 * WHY:  These are the calls whose Darwin form differs in semantics, not
 *       spelling; the portable tree calls brix_plat_* and never names the
 *       syscall (guard: tools/ci/check_platform_leak.py).
 * HOW:  Thin syscall wrappers. A kernel or filesystem without the feature
 *       answers ENOSYS (openat2) or ENOTSUP (renameat2 flags) so callers keep
 *       their existing fallbacks.
 */

/* The glibc feature-test macro these bodies need (openat2, renameat2, statx, RENAME_NOREPLACE).  Guarded, not
 * bare, because both real builds already pass -D_GNU_SOURCE on the command
 * line (./config for the module, client/Makefile's HARDEN for the client) and
 * an unguarded redefinition is an error under -Werror.  Declared HERE rather
 * than left to the caller so a standalone harness that links one PAL body --
 * every tests/cmdscripts compile line that reaches brix_plat_* -- gets the
 * prototypes too, instead of an implicit declaration and a silent link
 * failure.  It must precede every include, hence its place above them. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_LINUX

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int
brix_plat_openat2(int rootfd, const char *rel, int flags, mode_t mode,
    uint64_t resolve)
{
    struct open_how how;

    memset(&how, 0, sizeof(how));
    how.flags   = (uint64_t) (flags | O_CLOEXEC);
    how.resolve = resolve;
    if (flags & O_CREAT) {
        how.mode = (uint64_t) (mode & 07777);
    }
#if defined(SYS_openat2)
    return (int) syscall(SYS_openat2, rootfd, rel, &how, sizeof(how)); /* vfs-seam-allow: SEAM_CORRECT - PAL confinement primitive beneath brix_open_beneath */
#else
    (void) rootfd;
    errno = ENOSYS;
    return -1;
#endif
}

int
brix_plat_openat2_available(void)
{
    int fd = brix_plat_openat2(AT_FDCWD, ".", O_PATH, 0, 0);

    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return (errno != ENOSYS) ? 1 : 0;
}

int
brix_plat_stat_resolve(int rootfd, const char *rel, int nofollow,
    uint64_t resolve, struct stat *st)
{
    int fd, rc;

    fd = brix_plat_openat2(rootfd, rel[0] == '\0' ? "." : rel,
                           O_PATH | (nofollow ? O_NOFOLLOW : 0), 0, resolve);
    if (fd < 0) {
        return -1;
    }
    rc = fstat(fd, st); /* vfs-seam-allow: SEAM_CORRECT - fstat on the PAL-confined handle */
    close(fd);
    return rc;
}

int
brix_plat_unlinkat(int dirfd, const char *name, int flags)
{
    return unlinkat(dirfd, name, flags); /* vfs-seam-allow: SEAM_CORRECT - PAL unlink primitive beneath the VFS */
}

int
brix_plat_renameat2(int sfd, const char *sbase, int dfd, const char *dbase,
    unsigned int flags)
{
#if defined(SYS_renameat2)
    unsigned int kflags = 0;

    if (flags & BRIX_RENAME_NOREPLACE) {
        kflags |= 1u;            /* RENAME_NOREPLACE */
    }
    if (flags & BRIX_RENAME_EXCHANGE) {
        kflags |= 2u;            /* RENAME_EXCHANGE */
    }
    if (syscall(SYS_renameat2, sfd, sbase, dfd, dbase, kflags) == 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL rename primitive beneath the VFS */
        return 0;
    }
    if (errno == ENOSYS || errno == EINVAL) {
        errno = ENOTSUP;
    }
    return -1;
#else
    (void) sfd; (void) sbase; (void) dfd; (void) dbase; (void) flags;
    errno = ENOTSUP;
    return -1;
#endif
}

int
brix_plat_fstatat_btime(int dirfd, const char *name, int flags,
    struct stat *st, time_t *btime)
{
    struct statx stx;

    if (statx(dirfd, name, flags,
              STATX_BASIC_STATS | STATX_BTIME, &stx) != 0) /* vfs-seam-allow: SEAM_CORRECT - PAL metadata primitive beneath the VFS */
    {
        return -1;
    }
    memset(st, 0, sizeof(*st));
    st->st_mode  = (mode_t) stx.stx_mode;
    st->st_size  = (off_t) stx.stx_size;
    st->st_uid   = (uid_t) stx.stx_uid;
    st->st_gid   = (gid_t) stx.stx_gid;
    st->st_nlink = (nlink_t) stx.stx_nlink;
    st->st_ino   = (ino_t) stx.stx_ino;
    st->st_mtime = (time_t) stx.stx_mtime.tv_sec;
    st->st_atime = (time_t) stx.stx_atime.tv_sec;
    st->st_ctime = (time_t) stx.stx_ctime.tv_sec;
    *btime = (stx.stx_mask & STATX_BTIME) ? (time_t) stx.stx_btime.tv_sec : 0;
    return 0;
}

#endif /* BRIX_PLATFORM_LINUX */
