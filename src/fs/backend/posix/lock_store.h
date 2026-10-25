/* Portable, inode-bound lock-record transactions. Requires a POSIX host.
 * Call only after VFS policy, authorization and confinement have passed.
 * The caller owns a fresh, confined descriptor and closes it after the call.
 */
#pragma once
#include <stddef.h>

/* NULL expected requires absence; NULL replacement means compare-and-remove.
 * Returns 0 on success, -1/errno otherwise; never waits for another owner.
 * Every update requires the complete observed record, including expiry.
 */
int brix_posix_lock_store_update_fd(int descriptor,
    const void *expected, size_t expected_length,
    const void *replacement, size_t replacement_length);
