/*
 * src/platform/linux/posix_wrapper.c - Linux POSIX syscall wrappers
 * 
 * All Linux-specific syscall implementations live here.
 * Source code calls brix_plat_*() from platform_api.h - never these directly.
 */

#include "../platform.h"
#include "../platform_api.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if BRIX_PLATFORM_LINUX
#include <sys/random.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#endif

/* ==========================================================================
 * FILE DESCRIPTOR OPERATIONS
 * ========================================================================== */

#if BRIX_PLATFORM_LINUX

int
brix_plat_anon_fd(const char *name, const char *dir)
{
    (void)dir;  /* Linux memfd doesn't use directory */
    
    return memfd_create(name ? name : "anonymous", MFD_CLOEXEC);
}

int
brix_plat_fadvise(int fd, off_t offset, off_t len, int advice)
{
    return posix_fadvise(fd, offset, len, advice);
}

int
brix_plat_fsync_data(int fd)
{
    return fdatasync(fd);
}

void
brix_plat_sync(void)
{
    sync();
}

int
brix_plat_sync_tree(int dirfd)
{
    return syncfs(dirfd);
}

/* ==========================================================================
 * ZERO-COPY TRANSFERS
 * ========================================================================== */

ssize_t
brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    return sendfile(out_fd, in_fd, offset, count);
}

ssize_t
brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags)
{
    return splice(in_fd, NULL, out_fd, NULL, nbytes, flags);
}

ssize_t
brix_plat_copy_range(int in_fd, off_t *in_off,
                     int out_fd, off_t *out_off,
                     size_t len, unsigned int flags)
{
    (void)flags;  /* Linux copy_file_range doesn't use flags parameter */
    return copy_file_range(in_fd, in_off, out_fd, out_off, len, 0);
}

/* ==========================================================================
 * EVENT & NOTIFICATION
 * ========================================================================== */

int
brix_plat_eventfd(unsigned int initial_value, int flags)
{
    return eventfd(initial_value, flags);
}

int
brix_plat_pipe2(int pipefd[2], int flags)
{
    return pipe2(pipefd, flags);
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
    return getxattr(path, name, value, size);
}

ssize_t
brix_plat_fgetxattr(int fd, const char *name, void *value, size_t size)
{
    return fgetxattr(fd, name, value, size);
}

int
brix_plat_setxattr(const char *path, const char *name,
                   const void *value, size_t size, int flags)
{
    return setxattr(path, name, value, size, flags);
}

int
brix_plat_fsetxattr(int fd, const char *name,
                    const void *value, size_t size, int flags)
{
    return fsetxattr(fd, name, value, size, flags);
}

int
brix_plat_removexattr(const char *path, const char *name)
{
    return removexattr(path, name);
}

int
brix_plat_fremovexattr(int fd, const char *name)
{
    return fremovexattr(fd, name);
}

ssize_t
brix_plat_listxattr(const char *path, char *list, size_t size)
{
    return listxattr(path, list, size);
}

ssize_t
brix_plat_flistxattr(int fd, char *list, size_t size)
{
    return flistxattr(fd, list, size);
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
