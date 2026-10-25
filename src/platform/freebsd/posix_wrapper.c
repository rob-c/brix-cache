/* FreeBSD-only POSIX primitives. Shared anonymous-fd/sync bodies retain their
 * canonical owner in shared/cvmfs/platform/platform.c, as on Linux. */
#include "../platform_api.h"
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <unistd.h>

/* WHAT: Apply an advisory descriptor hint or return -1/errno.
 * WHY: POSIX returns error numbers directly; PAL callers expect errno.
 * HOW: Forward the native hint, normalizing the error convention. */
int brix_plat_fadvise(int descriptor, off_t offset, off_t length, int advice)
{
    int result = posix_fadvise(descriptor, offset, length, advice);
    if (result != 0) { errno = result; return -1; }
    return 0;
}

/* WHAT: Flush native filesystems. WHY: Preserve the PAL global barrier.
 * HOW: Use the host sync primitive. */
void brix_plat_sync(void) { sync(); }

/* WHAT: Transfer bytes and advance the offset by actual progress.
 * WHY: FreeBSD sendfile can return partial progress together with EAGAIN.
 * HOW: Bound the request, publish completed bytes, otherwise preserve errno. */
ssize_t brix_plat_sendfile(int destination, int source, off_t *offset, size_t count)
{
    off_t sent = 0;
    int result;
    if (offset == NULL || *offset < 0) { errno = EINVAL; return -1; }
    if (count == 0) { return 0; }
    if (count > SSIZE_MAX) { count = SSIZE_MAX; }
    result = sendfile(source, destination, *offset, count, NULL, &sent, 0); /* vfs-seam-allow: SEAM_CORRECT - native PAL sendfile */
    if (sent > 0) { *offset += sent; return (ssize_t) sent; }
    return result < 0 ? -1 : 0;
}

/* WHAT: Refuse unavailable splice. WHY: Do not fabricate successful transfers.
 * HOW: Return ENOSYS for the caller's buffered fallback. */
ssize_t brix_plat_splice(int source, int destination, size_t length, unsigned flags)
{ (void) source; (void) destination; (void) length; (void) flags; errno = ENOSYS; return -1; }

/* WHAT: Create the native event counter. WHY: Preserve counter semantics.
 * HOW: Translate the PAL's flags rather than assuming Linux flag values. */
int brix_plat_eventfd(unsigned initial, int flags)
{ return eventfd(initial, ((flags & BRIX_EVENTFD_CLOEXEC) ? EFD_CLOEXEC : 0)
                        | ((flags & BRIX_EVENTFD_NONBLOCK) ? EFD_NONBLOCK : 0)); }

/* WHAT: Return prior effective uid while switching, or query it with -1.
 * WHY: The broker reads back every transition. HOW: Use native euid operations. */
int brix_plat_setfsuid(uid_t uid)
{
    uid_t previous = geteuid();
    if (uid != (uid_t) -1 && seteuid(uid) != 0) { return -1; }
    return (int) previous;
}

/* WHAT: Return prior effective gid while switching, or query it with -1.
 * WHY: Match the existing PAL readback contract. HOW: Use native egid operations. */
int brix_plat_setfsgid(gid_t gid)
{
    gid_t previous = getegid();
    if (gid != (gid_t) -1 && setegid(gid) != 0) { return -1; }
    return (int) previous;
}

/* WHAT: Fill every requested byte with native entropy or fail on bad input.
 * WHY: Never use partial-read pseudo-random fallbacks. HOW: Use arc4random_buf. */
int brix_plat_random(void *buffer, size_t length)
{
    if (buffer == NULL && length != 0) { errno = EINVAL; return -1; }
    arc4random_buf(buffer, length);
    return 0;
}

/* WHAT: Replace this image using native PATH/environment semantics.
 * WHY: Spawning a surrogate would lose signal and process-identity contracts.
 * HOW: Call the host execvpe, preserving errors and the supplied environment. */
int brix_plat_execvpe(const char *file, char *const arguments[], char *const environment[])
{ extern char **environ; return execvpe(file, arguments, environment != NULL ? environment : environ); }

/* WHAT: Refuse unavailable full-width per-connection byte counters.
 * WHY: TCP_INFO sequence numbers are not cumulative byte counts and may wrap.
 * HOW: Clear outputs and return ENOTSUP; native RTT remains a client API. */
int brix_plat_tcp_stats(int descriptor, uint64_t *sent, uint64_t *received, uint32_t *rtt)
{
    (void) descriptor;
    if (sent == NULL || received == NULL || rtt == NULL) { errno = EINVAL; return -1; }
    *sent = 0; *received = 0; *rtt = 0;
    errno = ENOTSUP;
    return -1;
}
