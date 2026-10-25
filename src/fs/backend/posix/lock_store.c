/*
 * Portable inode-bound lock-store compare/exchange. Every cooperating writer
 * uses a fresh confined descriptor and the same nonblocking kernel flock.
 * Persisted xattrs remain storage truth for every protocol; no shadow DB.
 * This does NOT emulate general conditional xattrs for uncooperating writers.
 */
#include "lock_store.h"
#include "core/compat/lock_key.h"
#include "platform/platform_api.h"
#include <sys/file.h>
#include <string.h>

/* WHAT: Compare the current persisted value with the observed snapshot.
 * WHY: Stale refresh/unlock/expiry must not overwrite a successor's record.
 * HOW: NULL means absence; otherwise require exact length and bytes. A
 * truncated or unreadable value fails closed, never means an absent lock.
 */
static int
lock_store_compare(int descriptor, const void *expected, size_t length)
{
    unsigned char current[BRIX_LOCK_XATTR_MAXLEN];
    ssize_t count = fgetxattr(descriptor, BRIX_LOCK_XATTR_KEY,
                              current, sizeof(current));

    if (count < 0) {
        if (errno == ENODATA && expected == NULL) {
            return 0;
        }
        return -1;
    }
    if (expected == NULL) {
        errno = EEXIST;
        return -1;
    }
    if ((size_t) count != length || memcmp(current, expected, length) != 0) {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

/* WHAT: Apply a transaction while the inode's kernel lock is held.
 * WHY: No native conditional extattr syscall is needed by this store.
 * HOW: Compare, then perform one unconditional set or remove operation.
 */
static int
lock_store_apply(int descriptor, const void *expected, size_t expected_length,
    const void *replacement, size_t replacement_length)
{
    if (lock_store_compare(descriptor, expected, expected_length) != 0) {
        return -1;
    }
    if (replacement == NULL) {
        return fremovexattr(descriptor, BRIX_LOCK_XATTR_KEY);
    }
    return fsetxattr(descriptor, BRIX_LOCK_XATTR_KEY, replacement,
                     replacement_length, 0);
}

/* WHAT: Serialize one compare/exchange or refuse immediately on contention.
 * WHY: A process crash releases the lock; an untrusted contender cannot make
 * the event loop wait. An unrelated file lock must never be forcibly stolen.
 * HOW: Validate, reject special files, try-lock, compare/mutate and unlock.
 * Preserve the transaction errno; the caller closes its private descriptor.
 */
int
brix_posix_lock_store_update_fd(int descriptor,
    const void *expected, size_t expected_length,
    const void *replacement, size_t replacement_length)
{
    struct stat metadata;
    int result, saved_errno;

    if ((expected == NULL && replacement == NULL)
        || (expected == NULL && expected_length != 0)
        || (replacement == NULL && replacement_length != 0)
        || expected_length >= BRIX_LOCK_XATTR_MAXLEN
        || replacement_length >= BRIX_LOCK_XATTR_MAXLEN)
    {
        errno = EINVAL;
        return -1;
    }
    if (fstat(descriptor, &metadata) != 0) {
        return -1;
    }
    if (!S_ISREG(metadata.st_mode) && !S_ISDIR(metadata.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        return -1;
    }
    result = lock_store_apply(descriptor, expected, expected_length,
                               replacement, replacement_length);
    saved_errno = errno;
    (void) flock(descriptor, LOCK_UN);
    errno = saved_errno;
    return result;
}
