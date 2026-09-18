/*
 * src/platform/darwin/process_wrapper.c - Darwin descriptor, identity and privilege calls
 *
 * WHAT: The wake-descriptor pair (a pipe), accept + FD_CLOEXEC, LOCAL_PEERCRED,
 *       close-from loops, getgrouplist's int* shape and the process / boot
 *       identity reads (_NSGetExecutablePath, kern.bootsessionuuid). Privilege calls live
 *       in priv_wrapper.c. Pure libc, so the native client links this file too.
 * WHY:  Each was a private `#if defined(__APPLE__)` port scattered through
 *       src/auth, src/net and src/core; the portable tree now calls brix_plat_*.
 * HOW:  Emulations keep the pre-PAL behaviour exactly. Where Darwin has no
 *       counterpart (prctl, capget/capset) the gap is stated in
 *       src/platform/darwin/README.md rather than hidden in a caller.
 */

#include "../platform.h"
#include "../platform_api.h"
#include <stdint.h>
#include <sys/time.h>
#include <sys/event.h>

#if BRIX_PLATFORM_DARWIN

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/un.h>
#include <unistd.h>

static void
wakefd_apply(int fd, int flags)
{
    if (flags & BRIX_EVENTFD_CLOEXEC) {
        (void) fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    if (flags & BRIX_EVENTFD_NONBLOCK) {
        (void) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    }
}

int
brix_plat_wakefd_open(int *rfd, int *wfd, int flags)
{
    int pfd[2];

    if (pipe(pfd) != 0) {
        return -1;
    }
    wakefd_apply(pfd[0], flags);
    wakefd_apply(pfd[1], flags);
    *rfd = pfd[0];
    *wfd = pfd[1];
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
    ssize_t  n;

    /* a pipe accumulates one 8-byte record per signal: drain them all */
    for ( ;; ) {
        n = read(rfd, &counter, sizeof(counter));
        if (n > 0) {
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return (n == 0 || errno == EAGAIN) ? 0 : -1;
    }
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
    int fd = accept(sockfd, addr, addrlen);

    if (fd >= 0 && cloexec) {
        (void) fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
    }
    return fd;
}

int
brix_plat_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid)
{
    struct xucred xc;
    socklen_t     len = sizeof(xc);
    pid_t         peer = 0;
    socklen_t     plen = sizeof(peer);

    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &xc, &len) != 0) {
        return -1;
    }
    if (uid != NULL) { *uid = xc.cr_uid; }
    if (gid != NULL) { *gid = (xc.cr_ngroups > 0) ? xc.cr_groups[0] : (gid_t) -1; }
    if (pid != NULL) {
        *pid = (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peer, &plen) == 0)
               ? peer : 0;
    }
    return 0;
}

int
brix_plat_close_from(int lowfd)
{
    long maxfd = sysconf(_SC_OPEN_MAX);
    int  fd;

    if (maxfd < 0 || maxfd > 65536) {
        maxfd = 65536;
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
    short flags = 0;

    (void) fa;
    (void) lowfd;   /* CLOEXEC_DEFAULT keeps only what a file action dup2()s */
    /* Enumerating addclose() actions does not work here: a queued close of a
     * descriptor the child cannot close (Darwin's guarded libdispatch/XPC fds)
     * fails the whole posix_spawn with EBADF.  The Apple attribute closes
     * everything the file actions did not explicitly keep. */
    if (posix_spawnattr_getflags(attr, &flags) != 0) {
        return -1;
    }
    return posix_spawnattr_setflags(attr, (short) (flags | POSIX_SPAWN_CLOEXEC_DEFAULT));
}


int
brix_plat_getgrouplist(const char *user, gid_t base, gid_t *groups,
    int *ngroups)
{
    int  cap = *ngroups;
    int *ints;
    int  rc, i;

    if (cap <= 0) {
        errno = EINVAL;
        return -1;
    }
    ints = malloc((size_t) cap * sizeof(int));
    if (ints == NULL) {
        return -1;
    }
    rc = getgrouplist(user, (int) base, ints, ngroups);
    for (i = 0; i < *ngroups && i < cap; i++) {
        groups[i] = (gid_t) ints[i];
    }
    free(ints);
    return rc;
}

int
brix_plat_self_exe(char *buf, size_t cap)
{
    char     raw[PATH_MAX];
    char     real[PATH_MAX];
    uint32_t size = sizeof(raw);

    /* The dyld answer may hold "..", symlinks or a relative spelling; the
     * caller wants the file it can exec again, so canonicalise it. */
    if (_NSGetExecutablePath(raw, &size) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (realpath(raw, real) == NULL) {
        return -1;
    }
    if (strlen(real) >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, real, strlen(real) + 1);
    return 0;
}

int
brix_plat_boot_id(char *buf, size_t cap)
{
    size_t len = cap;

    if (cap == 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    /* A UUID minted at boot; sysctl NUL-terminates and fails ENOMEM when the
     * buffer is short, which is the ENAMETOOLONG of a fixed-size id. */
    if (sysctlbyname("kern.bootsessionuuid", buf, &len, NULL, 0) != 0) {
        if (errno == ENOMEM) {
            errno = ENAMETOOLONG;
        }
        return -1;
    }
    buf[cap - 1] = '\0';
    buf[strcspn(buf, "\n")] = '\0';
    if (buf[0] == '\0') {
        errno = ENODATA;
        return -1;
    }
    return 0;
}

#endif /* BRIX_PLATFORM_DARWIN */

/* Darwin has no pidfd: kqueue's EVFILT_PROC/NOTE_EXIT is the native form of
 * "tell me when this process exits", and kevent(2) takes the timeout directly.
 * A process that has already exited cannot be registered (ESRCH), which is
 * reported as "exited" — the same answer the caller would reach by waiting. */
int
brix_plat_wait_pid_timeout(pid_t pid, unsigned timeout_ms)
{
    struct kevent   ev;
    struct timespec ts;
    int             kq, n;

    kq = kqueue();
    if (kq < 0) {
        return 0;
    }
    EV_SET(&ev, (uintptr_t) pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT,
           0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
        (void) close(kq);
        return 0;
    }
    ts.tv_sec  = (time_t) (timeout_ms / 1000U);
    ts.tv_nsec = (long) (timeout_ms % 1000U) * 1000000L;
    do {
        n = kevent(kq, NULL, 0, &ev, 1, &ts);
    } while (n < 0 && errno == EINTR);
    (void) close(kq);
    return n == 0;                      /* no event before the deadline */
}
