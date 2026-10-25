/* Descriptor storage operations shared by the FreeBSD server and clients. */
#include "../platform_api.h"
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <string.h>
#include <unistd.h>

/* WHAT: Permit sendfile only for a known non-ZFS filesystem on this fd.
 * WHY: Native OpenZFS 2.4.2 and 2.4.4 deadlock page-busy/range locks when
 *      sendfile races a write; a read-only handle cannot exclude other writers.
 * HOW: 1. Query the open fd, never its pathname. 2. Refuse ZFS or an unknown
 *      filesystem. 3. Restore errno: this is a transport choice, not an error. */
int
brix_plat_file_sendfile_safe(int fd)
{
    struct statfs filesystem;
    int saved = errno;
    int safe = fstatfs(fd, &filesystem) == 0
        && filesystem.f_fstypename[0] != '\0'
        && strcmp(filesystem.f_fstypename, "zfs") != 0;

    errno = saved;
    return safe;
}

/* WHAT: Return a flagged pipe. WHY: Preserve descriptor inheritance rules.
 * HOW: Translate PAL flags to native atomic pipe2 flags. */
int brix_plat_pipe2(int descriptors[2], int flags)
{ return pipe2(descriptors, ((flags & BRIX_PIPE_CLOEXEC) ? O_CLOEXEC : 0)
                          | ((flags & BRIX_PIPE_NONBLOCK) ? O_NONBLOCK : 0)); }

/* WHAT: Copy a native descriptor range. WHY: Keep data syscalls behind the PAL.
 * HOW: Reject nonzero native flags; forward offsets without emulation. */
ssize_t brix_plat_copy_range(int source, off_t *source_offset, int destination,
                            off_t *destination_offset, size_t length, unsigned flags)
{ return copy_file_range(source, source_offset, destination, destination_offset, /* vfs-seam-allow: SEAM_CORRECT - native PAL data transfer */
                          length, flags); }

/* WHAT: Refuse unsupported beyond-EOF reservation. WHY: posix_fallocate changes
 * file size and is not KEEP_SIZE. HOW: Report EOPNOTSUPP for caller fallback. */
int brix_plat_reserve(int descriptor, off_t size)
{ (void) descriptor; (void) size; errno = EOPNOTSUPP; return -1; }

/* WHAT: Read a vector at an offset. WHY: No unrequested nonblocking semantics.
 * HOW: Reject unsupported flags rather than silently discarding them. */
ssize_t brix_plat_preadv2(int descriptor, const struct iovec *vector, int count,
                         off_t offset, int flags)
{
    if (flags != 0) { errno = ENOTSUP; return -1; }
    return preadv(descriptor, vector, count, offset); /* vfs-seam-allow: SEAM_CORRECT - native PAL descriptor IO */
}

/* WHAT: Write at EOF for append handles, otherwise at the supplied offset.
 * WHY: BSD pwrite honors its offset even on O_APPEND. HOW: Select the right verb. */
ssize_t brix_plat_pwrite_at(int descriptor, const void *data, size_t length,
                           off_t offset, int append)
{ return append ? write(descriptor, data, length) : pwrite(descriptor, data, length, offset); } /* vfs-seam-allow: SEAM_CORRECT - native PAL descriptor IO */

/* WHAT: Return a disk's native media size. WHY: Block devices have no st_size.
 * HOW: Query DIOCGMEDIASIZE and reject negative/native errors. */
int brix_plat_blockdev_size(int descriptor, uint64_t *bytes)
{
    off_t length;
    if (bytes == NULL) { errno = EINVAL; return -1; }
    if (ioctl(descriptor, DIOCGMEDIASIZE, &length) != 0) { return -1; }
    if (length < 0) { errno = EIO; return -1; }
    *bytes = (uint64_t) length;
    return 0;
}

/* WHAT: Refuse unsupported descriptor seals. WHY: Successful no-ops lie about
 * immutability. HOW: Return ENOTSUP so the caller can refuse or copy. */
int brix_plat_fd_seal(int descriptor)
{ (void) descriptor; errno = ENOTSUP; return -1; }

/* WHAT: Compare two open-file identities without trusting a recovered pathname.
 * WHY: A concurrent rename/replacement must not alias a different inode.
 * HOW: Compare both native device and inode numbers after reopening. */
static int
brix_freebsd_same_file(int original, int reopened)
{
    struct stat before, after;
    return fstat(original, &before) == 0 && fstat(reopened, &after) == 0 /* vfs-seam-allow: NOT_STORAGE - native descriptor identity check */
        && before.st_dev == after.st_dev && before.st_ino == after.st_ino;
}

/* WHAT: Return a close-on-exec readable alias of an already-open file.
 * WHY: FreeBSD has no Linux procfs reopen operation for unlinked write-only fds.
 * HOW: Reopen F_KINFO's name and check identity; otherwise duplicate only a
 * readable original, matching the existing BSD alias fallback contract. */
int
brix_plat_fd_reopen_readonly(int descriptor)
{
    struct kinfo_file info;
    int reopened, flags;

    memset(&info, 0, sizeof(info));
    info.kf_structsize = sizeof(info);
    if (fcntl(descriptor, F_KINFO, &info) == 0 && info.kf_path[0] == '/') {
        reopened = open(info.kf_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); /* vfs-seam-allow: NOT_STORAGE - native alias of an already-open file */
        if (reopened >= 0) {
            if (brix_freebsd_same_file(descriptor, reopened)) { return reopened; }
            close(reopened);
        }
    }
    flags = fcntl(descriptor, F_GETFL);
    if (flags >= 0 && (flags & O_ACCMODE) != O_WRONLY) {
        return fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
    }
    if (flags >= 0) { errno = EACCES; }
    return -1;
}
