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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <unistd.h>
#include <libkern/OSByteOrder.h>
#include <Security/Security.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* ---- Read Darwin's native TCP counters ----
 * WHAT: Return byte counts and microsecond RTT, or -1 with zeroed outputs.
 * WHY: Firefly must not publish fabricated zero usage on supported Darwin TCP.
 * HOW: 1. Validate outputs. 2. Query the native struct. 3. Translate RTT units.
 */
int
brix_plat_tcp_stats(int fd, uint64_t *sent, uint64_t *received, uint32_t *rtt_us)
{
    struct tcp_connection_info info;
    socklen_t length = sizeof(info);

    if (sent == NULL || received == NULL || rtt_us == NULL) {
        errno = EINVAL;
        return -1;
    }
    *sent = 0;
    *received = 0;
    *rtt_us = 0;
    memset(&info, 0, sizeof(info));
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &length) != 0) {
        return -1;
    }
    if (length < offsetof(struct tcp_connection_info, tcpi_rxbytes)
                 + sizeof(info.tcpi_rxbytes)) {
        errno = ENOTSUP;
        return -1;
    }
    *sent = info.tcpi_txbytes;
    *received = info.tcpi_rxbytes;
    *rtt_us = info.tcpi_srtt > UINT32_MAX / 1000u
              ? UINT32_MAX : info.tcpi_srtt * 1000u;
    return 0;
}

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
        unlink(template); /* vfs-seam-allow: SEAM_CORRECT - PAL anonymous descriptor lifetime */
    }
    return fd;
}

int
brix_plat_fadvise(int fd, off_t offset, off_t len, int advice)
{
    struct radvisory ra;

    if (advice == BRIX_FADV_NORMAL) {
        return fcntl(fd, F_NOCACHE, 0);
    }
    if (advice == BRIX_FADV_RANDOM) {
        return fcntl(fd, F_RDAHEAD, 0);
    }
    if (advice == BRIX_FADV_SEQUENTIAL) {
        return fcntl(fd, F_RDAHEAD, 1);
    }
    if (advice == BRIX_FADV_DONTNEED || advice == BRIX_FADV_NOREUSE) {
        return fcntl(fd, F_NOCACHE, 1);
    }
    if (advice != BRIX_FADV_WILLNEED || offset < 0 || len < 0) {
        errno = EINVAL;
        return -1;
    }
    ra.ra_offset = offset;
    ra.ra_count = len > INT_MAX ? INT_MAX : (int) len;
    return fcntl(fd, F_RDADVISE, &ra);
}

/* Whether to force the drive's write cache to media (F_FULLFSYNC, the Linux
 * fdatasync equivalent) or stop at the cache-level fsync(2).  F_FULLFSYNC is
 * the default: durability parity with Linux.  BRIX_PLAT_FSYNC_FULL=0 is a
 * development/test-host knob only — it costs ~28 ms per file on a laptop SSD
 * (50x fsync) and serialises every writer on the host. */
static int
darwin_fsync_full(void)
{
    static int cached = -1;

    if (cached < 0) {
        const char *knob = getenv("BRIX_PLAT_FSYNC_FULL");
        cached = (knob != NULL && knob[0] == '0' && knob[1] == '\0') ? 0 : 1;
    }
    return cached;
}

int
brix_plat_fsync_data(int fd)
{
    /* F_FULLFSYNC (guaranteed flush to physical media) unless disabled */
    if (darwin_fsync_full() && fcntl(fd, F_FULLFSYNC) == 0) {
        return 0;
    }
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
    return fcntl(dirfd, F_FULLFSYNC);
}

/* ==========================================================================
 * ZERO-COPY TRANSFERS
 * ========================================================================== */

ssize_t
brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    off_t sent;

    if (offset == NULL || *offset < 0) {
        errno = EINVAL;
        return -1;
    }
    if (count == 0) {
        return 0;
    }
    /* Darwin treats a zero input length as "through EOF", not zero bytes.
     * It also reports completed bytes alongside EAGAIN/EINTR: preserve that
     * progress so a caller never retransmits a partially sent region. */
    sent = count > (size_t) SSIZE_MAX ? (off_t) SSIZE_MAX : (off_t) count;
    if (sendfile(in_fd, out_fd, *offset, &sent, NULL, 0) < 0 /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
        && sent == 0)
    {
        return -1;
    }

    *offset += sent;
    return (ssize_t) sent;
}

ssize_t
brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags)
{
    /* macOS lacks splice - not implemented */
    (void)in_fd; (void)out_fd; (void)nbytes; (void)flags;
    errno = ENOSYS;
    return -1;
}

/* ==========================================================================
 * EVENT & NOTIFICATION
 * ========================================================================== */

int
brix_plat_eventfd(unsigned int initial_value, int flags)
{
    /* A pipe's read end is not a bidirectional eventfd counter. Returning it
     * lost the write end and falsely certified an unusable notification fd.
     * Portable callers use the existing paired notification-channel PAL. */
    (void) initial_value;
    (void) flags;
    errno = ENOTSUP;
    return -1;
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
    int fd = open("/dev/urandom", O_RDONLY); /* vfs-seam-allow: NOT_STORAGE - PAL entropy device */
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

/* Darwin reports a missing attribute as ENOATTR (93); Linux, and every
 * ENODATA check in the tree, expects ENODATA (96).  Normalise on failure. */
static ssize_t
darwin_xattr_rc(ssize_t rc)
{
    if (rc < 0 && errno == ENOATTR) {
        errno = ENODATA;
    }
    return rc;
}

/* Read-side (get/list/remove): Darwin limits names to XATTR_MAXNAMELEN (127)
 * where Linux allows 255 and reports ENAMETOOLONG; such a name cannot exist
 * here, so readers see it as absent.  Writes keep ENAMETOOLONG. */
static ssize_t
darwin_xattr_read_rc(ssize_t rc)
{
    if (rc < 0 && errno == ENAMETOOLONG) {
        errno = ENODATA;
    }
    return darwin_xattr_rc(rc);
}

ssize_t
brix_plat_getxattr(const char *path, const char *name, void *value, size_t size)
{
    /* macOS getxattr has 6 parameters (position, options) */
    return darwin_xattr_read_rc((getxattr)(path, name, value, size, 0, 0)); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_fgetxattr(int fd, const char *name, void *value, size_t size)
{
    return darwin_xattr_read_rc((fgetxattr)(fd, name, value, size, 0, 0)); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_setxattr(const char *path, const char *name,
                   const void *value, size_t size, int flags)
{
    /* macOS setxattr has 6 parameters */
    return darwin_xattr_rc((setxattr)(path, name, value, size, 0, flags)); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_fsetxattr(int fd, const char *name,
                    const void *value, size_t size, int flags)
{
    return darwin_xattr_rc((fsetxattr)(fd, name, value, size, 0, flags)); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_removexattr(const char *path, const char *name)
{
    /* macOS removexattr has 3 parameters (options) */
    return darwin_xattr_read_rc((removexattr)(path, name, 0)); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_fremovexattr(int fd, const char *name)
{
    return darwin_xattr_read_rc((fremovexattr)(fd, name, 0)); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_listxattr(const char *path, char *list, size_t size)
{
    /* macOS listxattr has 4 parameters (options) */
    return darwin_xattr_read_rc((listxattr)(path, list, size, 0)); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_flistxattr(int fd, char *list, size_t size)
{
    return darwin_xattr_read_rc((flistxattr)(fd, list, size, 0)); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

/* ==========================================================================
 * PROCESS EXECUTION
 * ========================================================================== */

int
brix_plat_execvpe(const char *file, char *const argv[], char *const envp[])
{
    /* SETEXEC replaces this process rather than spawning a surrogate child.
     * In particular, preserve signal termination and PATH-search semantics;
     * spawning + WEXITSTATUS lost both and changed the executed command PID. */
    posix_spawnattr_t attr;
    pid_t pid;
    int status;
    extern char **environ;

    status = posix_spawnattr_init(&attr);
    if (status != 0) {
        errno = status;
        return -1;
    }
    status = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
    if (status == 0) {
        status = posix_spawnp(&pid, file, NULL, &attr, argv,
                             envp != NULL ? envp : environ);
    }
    posix_spawnattr_destroy(&attr);
    /* A successful SETEXEC never returns. Refuse an impossible success too. */
    errno = status != 0 ? status : EIO;
    return -1;
}
