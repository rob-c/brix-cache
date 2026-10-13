/*
 * client/lib/platform/linux/mounts.c - the mount table for client tools
 *
 * WHAT: brix_plat_mounts_walk over /proc/self/mountinfo (or a test-supplied
 *       table path). The same parser as src/platform/linux/path_wrapper.c.
 * WHY:  `xrd mount` lists xrootdfs mounts without naming /proc itself.
 * HOW:  One destructive tokenizer per line; malformed lines are skipped.
 */

#include "platform/mounts_internal.h"

#if BRIX_PLATFORM_LINUX

int
brix_plat_mounts_walk(const char *table_path, brix_plat_mount_cb cb, void *arg)
{
    return brix_plat_mountinfo_walk(
        table_path != NULL ? table_path : "/proc/self/mountinfo", cb, arg);
}

#endif /* BRIX_PLATFORM_LINUX */
