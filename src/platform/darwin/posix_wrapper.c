/*
 * src/platform/darwin/posix_wrapper.c - macOS POSIX syscall wrappers
 * 
 * All macOS-specific syscall implementations live here.
 * Source code calls brix_plat_*() from platform_api.h - never these directly.
 */

#include "../platform.h"
#include "../platform_api.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <unistd.h>
#include <libkern/OSByteOrder.h>
#include <Security/Security.h>
#include <sys/syscall.h>
#include <sys/xattr.h>

/* ==========================================================================
 * FILE DESCRIPTOR OPERATIONS
 * ========================================================================== */

int
brix_plat_anon_fd(const char *name, const char *dir)
{
    char template[PATH_MAX];
    const char *tmpdir = dir ? dir : "/tmp";
    
    if (name != NULL && name[0] != '\0') {
        snprintf(template, sizeof(template), "%s/%s_XXXXXX", tmpdir, name);
    } else {
        snprintf(template, sizeof(template), "%s/brix_anon_XXXXXX", tmpdir);
    }
    
    int fd = mkstemp(template);
    if (fd >= 0) {
        int flags = fcntl(fd, F_GETFD);
        if (flags >= 0) {
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
        /* Unlink immediately so file is deleted when closed */
        unlink(template);
    }
    return fd;
}

int
brix_plat_fadvise(int fd, off_t offset, off_t len, int advice)
{
    /* macOS lacks posix_fadvise - no-op */
    (void)fd; (void)offset; (void)len; (void)advice;
    return 0;
}

int
brix_plat_fsync_data(int fd)
{
    /* Try F_FULLFSYNC first (guaranteed flush to physical media) */
    if (fcntl(fd, F_FULLFSYNC) == 0) {
        return 0;
    }
    /* Fallback to fsync */
    return fsync(fd);
}

void
brix_plat_sync(void)
{
    sync();
}

int
brix_plat_sync_tree(int dirfd)
{
    /* macOS lacks syncfs - use global sync() */
    (void)dirfd;
    sync();
    return 0;
}

/* ==========================================================================
 * ZERO-COPY TRANSFERS
 * ========================================================================== */

ssize_t
brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    off_t sbytes = 0;
    int sfcount = 0;
    struct sf_hdtr hdtr;
    
    memset(&hdtr, 0, sizeof(hdtr));
    
    /* macOS sendfile signature differs from Linux */
    if (sendfile(in_fd, out_fd, *offset, &sbytes, &hdtr, sfcount) < 0) {
        return -1;
    }
    
    *offset += sbytes;
    return (ssize_t)sbytes;
}

ssize_t
brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags)
{
    /* macOS lacks splice - not implemented */
    (void)in_fd; (void)out_fd; (void)nbytes; (void)flags;
    errno = ENOSYS;
    return -1;
}

ssize_t
brix_plat_copy_range(int in_fd, off_t *in_off,
                     int out_fd, off_t *out_off,
                     size_t len, unsigned int flags)
{
    /* macOS lacks copy_file_range - use buffered copy */
    (void)in_fd; (void)in_off; (void)out_fd; (void)out_off;
    (void)len; (void)flags;
    errno = ENOSYS;
    return -1;
}

/* ==========================================================================
 * EVENT & NOTIFICATION
 * ========================================================================== */

int
brix_plat_eventfd(unsigned int initial_value, int flags)
{
    int pipefd[2];
    
    /* macOS lacks eventfd - use pipe as fallback */
    if (pipe(pipefd) < 0) {
        return -1;
    }
    
    /* Apply flags via fcntl */
    if (flags & BRIX_EVENTFD_CLOEXEC) {
        fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    }
    
    if (flags & BRIX_EVENTFD_NONBLOCK) {
        int fflags;
        fflags = fcntl(pipefd[0], F_GETFL, 0);
        fcntl(pipefd[0], F_SETFL, fflags | O_NONBLOCK);
        fflags = fcntl(pipefd[1], F_GETFL, 0);
        fcntl(pipefd[1], F_SETFL, fflags | O_NONBLOCK);
    }
    
    /* Return read end - caller manages both ends */
    return pipefd[0];
}

int
brix_plat_pipe2(int pipefd[2], int flags)
{
    if (pipe(pipefd) < 0) {
        return -1;
    }
    
    /* Apply flags via fcntl */
    if (flags & BRIX_PIPE_CLOEXEC) {
        fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    }
    
    if (flags & BRIX_PIPE_NONBLOCK) {
        int fflags;
        fflags = fcntl(pipefd[0], F_GETFL, 0);
        fcntl(pipefd[0], F_SETFL, fflags | O_NONBLOCK);
        fflags = fcntl(pipefd[1], F_GETFL, 0);
        fcntl(pipefd[1], F_SETFL, fflags | O_NONBLOCK);
    }
    
    return 0;
}

/* ==========================================================================
 * SECURITY & CONFINEMENT
 * ========================================================================== */

int
brix_plat_setfsuid(uid_t uid)
{
    /* macOS lacks setfsuid - use seteuid (affects both real and effective) */
    return seteuid(uid);
}

int
brix_plat_setfsgid(gid_t gid)
{
    /* macOS lacks setfsgid - use setegid */
    return setegid(gid);
}

/* ==========================================================================
 * RANDOM NUMBER GENERATION
 * ========================================================================== */

int
brix_plat_random(void *buf, size_t len)
{
    if (SecRandomCopyBytes(kSecRandomDefault, len, (uint8_t *)buf) == errSecSuccess) {
        return 0;
    }
    
    /* Fallback to /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    ssize_t n = read(fd, buf, len);
    close(fd);
    
    return (n == (ssize_t)len) ? 0 : -1;
}

/* ==========================================================================
 * EXTENDED ATTRIBUTES
 * ========================================================================== */

ssize_t
brix_plat_getxattr(const char *path, const char *name, void *value, size_t size)
{
    /* macOS getxattr has 6 parameters (position, options) */
    return getxattr(path, name, value, size, 0, 0);
}

ssize_t
brix_plat_fgetxattr(int fd, const char *name, void *value, size_t size)
{
    return fgetxattr(fd, name, value, size, 0, 0);
}

int
brix_plat_setxattr(const char *path, const char *name,
                   const void *value, size_t size, int flags)
{
    /* macOS setxattr has 6 parameters */
    return setxattr(path, name, value, size, 0, flags);
}

int
brix_plat_fsetxattr(int fd, const char *name,
                    const void *value, size_t size, int flags)
{
    return fsetxattr(fd, name, value, size, 0, flags);
}

int
brix_plat_removexattr(const char *path, const char *name)
{
    /* macOS removexattr has 3 parameters (options) */
    return removexattr(path, name, 0);
}

int
brix_plat_fremovexattr(int fd, const char *name)
{
    return fremovexattr(fd, name, 0);
}

ssize_t
brix_plat_listxattr(const char *path, char *list, size_t size)
{
    /* macOS listxattr has 4 parameters (options) */
    return listxattr(path, list, size, 0);
}

ssize_t
brix_plat_flistxattr(int fd, char *list, size_t size)
{
    return flistxattr(fd, list, size, 0);
}

/* ==========================================================================
 * PROCESS EXECUTION
 * ========================================================================== */

int
brix_plat_execvpe(const char *file, char *const argv[], char *const envp[])
{
    /* macOS lacks execvpe - use posix_spawn for PATH search */
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    pid_t pid;
    int status;
    extern char **environ;
    
    if (posix_spawn_file_actions_init(&fa) != 0) {
        return -1;
    }
    
    if (posix_spawnattr_init(&attr) != 0) {
        posix_spawn_file_actions_destroy(&fa);
        return -1;
    }
    
    status = posix_spawn(&pid, file, &fa, &attr, argv, envp ? envp : environ);
    
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&fa);
    
    if (status != 0) {
        errno = status;
        return -1;
    }
    
    /* Wait for child - this blocks, but execvpe doesn't return either */
    waitpid(pid, &status, 0);
    
    /* If we get here, child exited - mimic execvpe behavior */
    _exit(WEXITSTATUS(status));
}
