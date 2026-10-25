/* FreeBSD descriptor, peer-identity and process-lifecycle primitives. */
#include "../platform_api.h"
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/un.h>
#include <sys/eventfd.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid.h>

/* WHAT: Open a native counter channel. WHY: Preserve paired descriptor ABI.
 * HOW: Translate PAL flags and publish only a successfully opened eventfd. */
int brix_plat_wakefd_open(int *reader, int *writer, int flags)
{
    int descriptor = eventfd(0, ((flags & BRIX_EVENTFD_CLOEXEC) ? EFD_CLOEXEC : 0)
                              | ((flags & BRIX_EVENTFD_NONBLOCK) ? EFD_NONBLOCK : 0));
    if (descriptor < 0) { return -1; }
    *reader = descriptor;
    *writer = descriptor;
    return 0;
}

/* WHAT: Signal once or return native error. WHY: Do not lose wakeups silently.
 * HOW: Write one complete counter value. */
int brix_plat_wakefd_signal(int descriptor)
{ uint64_t one = 1; return write(descriptor, &one, sizeof(one)) == sizeof(one) ? 0 : -1; }

/* WHAT: Drain a counter, accepting an already-empty channel.
 * WHY: EAGAIN is the nonblocking empty state. HOW: Read one complete value. */
int brix_plat_wakefd_drain(int descriptor)
{
    uint64_t value;
    if (read(descriptor, &value, sizeof(value)) == sizeof(value)) { return 0; }
    return errno == EAGAIN ? 0 : -1;
}

/* WHAT: Close each owned descriptor once. WHY: Native eventfd uses one fd.
 * HOW: Close nonnegative distinct entries only. */
void brix_plat_wakefd_close(int reader, int writer)
{
    if (reader >= 0) { close(reader); }
    if (writer >= 0 && writer != reader) { close(writer); }
}

/* WHAT: Accept with atomic close-on-exec. WHY: Avoid descriptor inheritance races.
 * HOW: Pass the native flag at descriptor creation. */
int brix_plat_accept4(int descriptor, struct sockaddr *address, socklen_t *length, int cloexec)
{ return accept4(descriptor, address, length, cloexec ? SOCK_CLOEXEC : 0); }

/* WHAT: Return kernel-reported local peer uid/gid/pid, never guessed values.
 * WHY: The impersonation broker authenticates its worker through this boundary.
 * HOW: Check xucred length/version and require a positive requested peer PID. */
int brix_plat_peer_cred(int descriptor, uid_t *uid, gid_t *gid, pid_t *pid)
{
    struct xucred credential;
    socklen_t length = sizeof(credential);

    memset(&credential, 0, sizeof(credential));
    if (getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERCRED, &credential, &length) != 0) {
        return -1;
    }
    if (length != sizeof(credential) || credential.cr_version != XUCRED_VERSION
        || credential.cr_ngroups < 1 || (pid != NULL && credential.cr_pid <= 0)) {
        errno = EACCES;
        return -1;
    }
    if (uid != NULL) { *uid = credential.cr_uid; }
    if (gid != NULL) { *gid = credential.cr_gid; }
    if (pid != NULL) { *pid = credential.cr_pid; }
    return 0;
}

/* WHAT: Close exactly the requested fd interval. WHY: Preserve caller-owned fds.
 * HOW: Use the kernel's interval primitive without directory scans. */
int brix_plat_close_range(unsigned first, unsigned last)
{ return close_range(first, last, 0); }

/* WHAT: Close all descriptors at/above lowfd. WHY: Child processes must not
 * inherit client sockets or keys. HOW: Use native closefrom. */
int brix_plat_close_from(int lowfd)
{ if (lowfd < 0) { errno = EINVAL; return -1; } closefrom(lowfd); return 0; }

/* WHAT: Add a child-only descriptor closure. WHY: Parent descriptors stay live.
 * HOW: Use FreeBSD's spawn action, propagating its POSIX error code. */
int brix_plat_spawn_closefrom(posix_spawn_file_actions_t *actions,
                             posix_spawnattr_t *attributes, int lowfd)
{ (void) attributes; return posix_spawn_file_actions_addclosefrom_np(actions, lowfd); }

/* WHAT: Return the native supplementary group list. WHY: Preserve native NSS.
 * HOW: Delegate with the caller's count/capacity contract. */
int brix_plat_getgrouplist(const char *user, gid_t base, gid_t *groups, int *count)
{ return getgrouplist(user, base, groups, count); }

/* WHAT: Return the canonical current executable path, never a truncated prefix.
 * WHY: Helpers must execute the exact installed image. HOW: Query and realpath. */
int brix_plat_self_exe(char *output, size_t capacity)
{
    int selector[] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
    char path[PATH_MAX], canonical[PATH_MAX];
    size_t length = sizeof(path);

    if (sysctl(selector, 4, path, &length, NULL, 0) != 0) { return -1; }
    if (length == 0 || length > sizeof(path) || path[length - 1] != '\0') {
        errno = EIO; return -1;
    }
    if (realpath(path, canonical) == NULL) { return -1; }
    length = strlen(canonical) + 1;
    if (output == NULL || length > capacity) { errno = ENAMETOOLONG; return -1; }
    memcpy(output, canonical, length);
    return 0;
}

/* WHAT: Return FreeBSD's actual per-boot UUID, not the persistent host UUID.
 * WHY: Recovery fences must distinguish a reboot with reused process IDs.
 * HOW: Query the native UUID and render it without accepting truncation. */
int brix_plat_boot_id(char *output, size_t capacity)
{
    uuid_t identifier;
    uint32_t status;
    size_t length = sizeof(identifier);
    char *text = NULL;

    if (sysctlbyname("kern.boot_id", &identifier, &length, NULL, 0) != 0) { return -1; }
    if (length != sizeof(identifier)) { errno = EIO; return -1; }
    uuid_to_string(&identifier, &text, &status);
    if (status != uuid_s_ok || text == NULL) { free(text); errno = EIO; return -1; }
    length = strlen(text) + 1;
    if (output == NULL || length > capacity) { free(text); errno = ENAMETOOLONG; return -1; }
    memcpy(output, text, length);
    free(text);
    return 0;
}

/* WHAT: Wait for exit without reaping, returning 1 only on the deadline.
 * WHY: Let the owning lifecycle code collect its own child status.
 * HOW: Use kqueue NOTE_EXIT and a monotonic absolute deadline across EINTR. */
int brix_plat_wait_pid_timeout(pid_t pid, unsigned timeout_ms)
{
    struct kevent event;
    struct timespec started, now, remaining;
    uint64_t deadline, current;
    int queue = kqueue(), ready;

    if (queue < 0) { return 0; }
    EV_SET(&event, (uintptr_t) pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent(queue, &event, 1, NULL, 0, NULL) < 0) { close(queue); return 0; }
    clock_gettime(CLOCK_MONOTONIC, &started);
    deadline = (uint64_t) started.tv_sec * 1000000000u + started.tv_nsec
               + (uint64_t) timeout_ms * 1000000u;
    do {
        clock_gettime(CLOCK_MONOTONIC, &now);
        current = (uint64_t) now.tv_sec * 1000000000u + now.tv_nsec;
        current = deadline > current ? deadline - current : 0;
        remaining.tv_sec = (time_t) (current / 1000000000u);
        remaining.tv_nsec = (long) (current % 1000000000u);
        ready = kevent(queue, NULL, 0, &event, 1, &remaining);
    } while (ready < 0 && errno == EINTR);
    close(queue);
    return ready == 0;
}
