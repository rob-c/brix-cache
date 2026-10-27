/*
 * test_fs_usage_arithmetic.c — fail-closed statvfs capacity arithmetic.
 *
 * SUCCESS: ordinary block counts produce exact byte and occupancy values.
 * ERROR: zero-size and internally inconsistent filesystem reports are refused.
 * SECURITY-NEG: a block-count product beyond uint64_t is refused, never wrapped.
 */

#include "core/compat/fs_usage.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
    struct statvfs vfs;
    brix_fs_usage_t usage;
    brix_fs_usage_t unchanged;

    memset(&vfs, 0, sizeof(vfs));
    vfs.f_frsize = 4096;
    vfs.f_blocks = 100;
    vfs.f_bfree = 40;
    vfs.f_bavail = 30;
    assert(brix_fs_usage_from_statvfs(&vfs, &usage) == NGX_OK);
    assert(usage.total_bytes == 409600);
    assert(usage.free_bytes == 163840);
    assert(usage.available_bytes == 122880);
    assert(usage.used_bytes == 245760);
    assert(usage.occupancy_bytes == 286720);

    unchanged = usage;
    vfs.f_bfree = 101;
    assert(brix_fs_usage_from_statvfs(&vfs, &usage) == NGX_ERROR);
    assert(memcmp(&usage, &unchanged, sizeof(usage)) == 0);

    vfs.f_bfree = 0;
    vfs.f_bavail = 0;
    vfs.f_blocks = (fsblkcnt_t) (UINT64_MAX / 2 + 1);
    vfs.f_frsize = 2;
    assert(brix_fs_usage_from_statvfs(&vfs, &usage) == NGX_ERROR);
    assert(memcmp(&usage, &unchanged, sizeof(usage)) == 0);

    vfs.f_blocks = 1;
    vfs.f_frsize = 0;
    vfs.f_bsize = 0;
    assert(brix_fs_usage_from_statvfs(&vfs, &usage) == NGX_ERROR);
    assert(memcmp(&usage, &unchanged, sizeof(usage)) == 0);

    puts("test_fs_usage_arithmetic: all checks passed");
    return 0;
}
