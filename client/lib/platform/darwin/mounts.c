/*
 * client/lib/platform/darwin/mounts.c - the mount table for client tools
 *
 * WHAT: brix_plat_mounts_walk over getmntinfo(3).
 * WHY:  `xrd mount` lists xrootdfs mounts on macOS too, not only Linux.
 * HOW:  MNT_NOWAIT snapshot; the table path argument is ignored.
 */

#include "platform/platform.h"

#if BRIX_PLATFORM_DARWIN

#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ucred.h>

int
brix_plat_mounts_walk(const char *table_path, brix_plat_mount_cb cb, void *arg)
{
    struct statfs *mnt;
    int            n, i, rc = 0;

    (void) table_path;
    n = getmntinfo(&mnt, MNT_NOWAIT);
    if (n <= 0) {
        return (n < 0) ? -1 : 0;
    }
    for (i = 0; i < n && rc == 0; i++) {
        rc = cb(mnt[i].f_mntonname, mnt[i].f_fstypename, mnt[i].f_mntfromname,
                arg);
    }
    return rc;
}

#endif /* BRIX_PLATFORM_DARWIN */
