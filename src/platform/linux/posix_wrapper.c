/*
 * src/platform/linux/posix_wrapper.c - Linux POSIX syscall wrappers
 * 
 * All Linux-specific syscall implementations live here.
 * Source code calls brix_plat_*() from platform_api.h - never these directly.
 */

/* The glibc feature-test macro these bodies need (execvpe, splice).  Guarded, not
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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#if BRIX_PLATFORM_LINUX
#include <sys/random.h>
#include <sys/sendfile.h>   /* sendfile(2); Darwin declares its own in <sys/socket.h> */
#include <sys/syscall.h>
#include <sys/fsuid.h>
#include <sys/xattr.h>
#include <linux/memfd.h>
#endif

/* ==========================================================================
 * FILE DESCRIPTOR OPERATIONS
 * ========================================================================== */

#if BRIX_PLATFORM_LINUX

/* Anonymous descriptors and data/tree sync retain their shared implementations
 * in shared/cvmfs/platform/platform.c, including the spill-file fallback. */

int
brix_plat_fadvise(int fd, off_t offset, off_t len, int advice)
{
    return posix_fadvise(fd, offset, len, advice);
}

void
brix_plat_sync(void)
{
    sync();
}

/* ==========================================================================
 * ZERO-COPY TRANSFERS
 * ========================================================================== */

ssize_t
brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    return sendfile(out_fd, in_fd, offset, count); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags)
{
    return splice(in_fd, NULL, out_fd, NULL, nbytes, flags);
}

/* ==========================================================================
 * EVENT & NOTIFICATION
 * ========================================================================== */

int
brix_plat_eventfd(unsigned int initial_value, int flags)
{
    /* BRIX_EVENTFD_* are PAL values, not the kernel's EFD_* bits */
    return eventfd(initial_value,
                   ((flags & BRIX_EVENTFD_CLOEXEC) ? EFD_CLOEXEC : 0)
                   | ((flags & BRIX_EVENTFD_NONBLOCK) ? EFD_NONBLOCK : 0));
}

/* ==========================================================================
 * SECURITY & CONFINEMENT
 * ========================================================================== */

int
brix_plat_setfsuid(uid_t uid)
{
    return setfsuid(uid);
}

int
brix_plat_setfsgid(gid_t gid)
{
    return setfsgid(gid);
}

/* ==========================================================================
 * RANDOM NUMBER GENERATION
 * ========================================================================== */

int
brix_plat_random(void *buf, size_t len)
{
    ssize_t n = getrandom(buf, len, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}

/* ==========================================================================
 * EXTENDED ATTRIBUTES
 * ========================================================================== */

ssize_t
brix_plat_getxattr(const char *path, const char *name, void *value, size_t size)
{
    return getxattr(path, name, value, size); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_fgetxattr(int fd, const char *name, void *value, size_t size)
{
    return fgetxattr(fd, name, value, size); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_setxattr(const char *path, const char *name,
                   const void *value, size_t size, int flags)
{
    return setxattr(path, name, value, size, flags); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_fsetxattr(int fd, const char *name,
                    const void *value, size_t size, int flags)
{
    return fsetxattr(fd, name, value, size, flags); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_removexattr(const char *path, const char *name)
{
    return removexattr(path, name); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_fremovexattr(int fd, const char *name)
{
    return fremovexattr(fd, name); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_listxattr(const char *path, char *list, size_t size)
{
    return listxattr(path, list, size); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_flistxattr(int fd, char *list, size_t size)
{
    return flistxattr(fd, list, size); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

/* ==========================================================================
 * PROCESS EXECUTION
 * ========================================================================== */

int
brix_plat_execvpe(const char *file, char *const argv[], char *const envp[])
{
    extern char **environ;
    return execvpe(file, argv, envp ? envp : environ);
}

#endif /* BRIX_PLATFORM_LINUX */

