/*
 * src/platform/linux/process_wrapper.c - Linux descriptor, identity and privilege calls
 *
 * WHAT: The wake-descriptor pair, accept4, SO_PEERCRED, close_from, the
 *       posix_spawn close-from action, getgrouplist and the process / boot
 *       identity reads (/proc/self/exe, boot_id) declared in
 *       platform_api_posix.h. Privilege calls live in priv_wrapper.c.
 * WHY:  Each has a Darwin form with different semantics; the portable tree
 *       calls brix_plat_* and never names the Linux call. Pure libc, so the
 *       native client links this file too (client/Makefile PLATFORM_SRCS).
 * HOW:  Thin wrappers over glibc and raw syscalls; nothing here is policy.
 */

/* The glibc feature-test macro these bodies need (accept4, getgrouplist, pidfd).  Guarded, not
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
#include <poll.h>

#if BRIX_PLATFORM_LINUX

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int
wakefd_kflags(int flags)
{
    return ((flags & BRIX_EVENTFD_CLOEXEC) ? EFD_CLOEXEC : 0)
           | ((flags & BRIX_EVENTFD_NONBLOCK) ? EFD_NONBLOCK : 0);
}

int
brix_plat_wakefd_open(int *rfd, int *wfd, int flags)
{
    int efd = eventfd(0, wakefd_kflags(flags));

    if (efd < 0) {
        return -1;
    }
    *rfd = efd;
    *wfd = efd;
    return 0;
}

int
brix_plat_wakefd_signal(int wfd)
{
    uint64_t one = 1;

    return (write(wfd, &one, sizeof(one)) == (ssize_t) sizeof(one)) ? 0 : -1;
}

int
brix_plat_wakefd_drain(int rfd)
{
    uint64_t counter;

    if (read(rfd, &counter, sizeof(counter)) == (ssize_t) sizeof(counter)) {
        return 0;
    }
    return (errno == EAGAIN) ? 0 : -1;
}

void
brix_plat_wakefd_close(int rfd, int wfd)
{
    if (rfd >= 0) {
        close(rfd);
    }
    if (wfd >= 0 && wfd != rfd) {
        close(wfd);
    }
}

int
brix_plat_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    int cloexec)
{
    return accept4(sockfd, addr, addrlen, cloexec ? SOCK_CLOEXEC : 0);
}

int
brix_plat_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid)
{
    struct ucred cred;
    socklen_t    len = sizeof(cred);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return -1;
    }
    if (uid != NULL) { *uid = cred.uid; }
    if (gid != NULL) { *gid = cred.gid; }
    if (pid != NULL) { *pid = cred.pid; }
    return 0;
}

/* /proc/self/fd names every open descriptor: close the numeric ones >= lowfd
 * (skipping the directory stream's own fd). 0 when the scan ran, -1 if /proc
 * is unavailable so the caller falls back to a bounded loop. */
static int
close_from_procfs(int lowfd)
{
    DIR           *dp = opendir("/proc/self/fd"); /* vfs-seam-allow: NOT_STORAGE - PAL fd hygiene before exec */
    struct dirent *de;
    int            self;

    if (dp == NULL) {
        return -1;
    }
    self = dirfd(dp);
    while ((de = readdir(dp)) != NULL) { /* vfs-seam-allow: NOT_STORAGE - PAL fd hygiene before exec */
        int fd = (int) strtol(de->d_name, NULL, 10);

        if (fd >= lowfd && fd != self && de->d_name[0] >= '0'
            && de->d_name[0] <= '9')
        {
            close(fd);
        }
    }
    closedir(dp);
    return 0;
}

int
brix_plat_close_from(int lowfd)
{
    long maxfd;
    int  fd;

#if defined(SYS_close_range)
    if (syscall(SYS_close_range, (unsigned int) lowfd, ~0U, 0) == 0) {
        return 0;
    }
#endif
    if (close_from_procfs(lowfd) == 0) {
        return 0;
    }
    maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0) {
        maxfd = 4096;
    }
    for (fd = lowfd; fd < maxfd; fd++) {
        close(fd);
    }
    return 0;
}

int
brix_plat_spawn_closefrom(posix_spawn_file_actions_t *fa,
    posix_spawnattr_t *attr, int lowfd)
{
    (void) attr;
    return posix_spawn_file_actions_addclosefrom_np(fa, lowfd);
}

int
brix_plat_getgrouplist(const char *user, gid_t base, gid_t *groups,
    int *ngroups)
{
    return getgrouplist(user, base, groups, ngroups);
}

int
brix_plat_self_exe(char *buf, size_t cap)
{
    ssize_t n;

    if (cap == 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    n = readlink("/proc/self/exe", buf, cap - 1); /* vfs-seam-allow: SEAM_CORRECT - PAL body reading procfs, not storage */
    if (n < 0) {
        return -1;
    }
    if ((size_t) n >= cap - 1) {
        errno = ENAMETOOLONG;   /* truncated: a partial path is no path */
        return -1;
    }
    buf[n] = '\0';
    return 0;
}

int
brix_plat_boot_id(char *buf, size_t cap)
{
    char    line[64];   /* a 36-char UUID and its newline, with room to spare */
    int     fd;
    ssize_t n;
    size_t  len;

    if (cap == 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC); /* vfs-seam-allow: SEAM_CORRECT - PAL body reading procfs, not storage */
    if (fd < 0) {
        return -1;
    }
    /* Read the id whole, into a local, and only then check that it fits.
     * Reading cap-1 bytes straight into `buf` handed the caller a PREFIX of
     * the boot id and called it success; two boots sharing that prefix then
     * compare equal, so brixcvmfs would read a stale transaction lock as live.
     * brix_plat_self_exe above already refuses a truncated answer and Darwin's
     * sysctl form fails ENOMEM on a short buffer — this is the same rule. */
    n = read(fd, line, sizeof(line) - 1); /* vfs-seam-allow: SEAM_CORRECT - PAL body reading procfs, not storage */
    close(fd);
    if (n < 0) {
        return -1;
    }
    line[n] = '\0';
    line[strcspn(line, "\n")] = '\0';
    len = strlen(line);
    if (len == 0) {
        errno = ENODATA;
        return -1;
    }
    if (len >= cap) {
        errno = ENAMETOOLONG;   /* truncated: a partial boot id is no boot id */
        return -1;
    }
    memcpy(buf, line, len + 1);
    return 0;
}

#endif /* BRIX_PLATFORM_LINUX */

/* pidfd_open(2) (Linux >= 5.3, same number on every architecture) gives a
 * descriptor that becomes readable when the process exits, so one poll(2)
 * enforces the deadline without SIGALRM and without a waitpid(WNOHANG) spin.
 * A kernel without it answers "exited", degrading to an unbounded wait. */
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

int
brix_plat_wait_pid_timeout(pid_t pid, unsigned timeout_ms)
{
    struct pollfd pfd;
    int           pidfd = (int) syscall(__NR_pidfd_open, pid, 0U);
    int           r;

    if (pidfd < 0) {
        return 0;
    }
    pfd.fd = pidfd;
    pfd.events = POLLIN;
    while ((r = poll(&pfd, 1, (int) timeout_ms)) < 0 && errno == EINTR) {
        /* the caller installs no handlers: restart the window */
    }
    (void) close(pidfd);
    return r == 0;
}
