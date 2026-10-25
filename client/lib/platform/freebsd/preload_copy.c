/* FreeBSD kernel-copy entry point for the POSIX preload frontend.
 *
 * Shadow descriptors are remote handles, not kernel regular files. Refuse
 * that file type without touching data/offsets so callers can use read/write.
 * Ordinary descriptors retain the native kernel operation and error contract.
 */
#include "brixposix_internal.h"
#include <errno.h>

/* ---- Route native copies or refuse remote offload ----
 * WHAT: Delegate ordinary copies, or return -1 with an explicit errno.
 * WHY: Passing a shadow descriptor into the kernel produces misleading EBADF
 *      and prevents native cp from choosing its supported read/write fallback.
 * HOW: 1. Recognize remote slots without dereferencing caller offsets.
 *      2. Reject unknown flags or unavailable offload without mutation.
 *      3. Delegate real descriptors through the existing libc resolver.
 */
ssize_t
copy_file_range( /* vfs-seam-allow: SEAM_CORRECT — ABI entry, not a raw copy call */
    int input, off_t *input_offset, int output,
    off_t *output_offset, size_t length, unsigned int flags)
{
    unsigned int supported_flags = 0;

#ifdef COPY_FILE_RANGE_CLONE
    supported_flags = COPY_FILE_RANGE_CLONE;
#endif
    if (slot_of(input) != NULL || slot_of(output) != NULL) {
        /* EINVAL is the native non-regular-file contract; a forced clone
         * must instead report unavailable cloning, never copy its bytes. */
        errno = flags != 0 && !(flags & ~supported_flags) ? EOPNOTSUPP : EINVAL;
        return -1;
    }
    REAL(copy_file_range);
    if (real_copy_file_range == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_copy_file_range(input, input_offset, output, output_offset,
                                length, flags);
}
