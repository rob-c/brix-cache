/* Native FreeBSD mount-table snapshots for client mount diagnostics. */
#include "platform/mounts_internal.h"
#include <sys/param.h>
#include <sys/mount.h>

/* WHAT: Visit native mounts or an explicit portable fixture snapshot.
 * WHY: FreeBSD does not expose Linux /proc/self/mountinfo.
 * HOW: Take a nonblocking mount snapshot and respect callback termination. */
int brix_plat_mounts_walk(const char *table, brix_plat_mount_cb callback, void *argument)
{
    struct statfs *mounts;
    int count, result = 0;
    if (table != NULL) { return brix_plat_mountinfo_walk(table, callback, argument); }
    count = getmntinfo(&mounts, MNT_NOWAIT);
    if (count <= 0) { return count < 0 ? -1 : 0; }
    for (int index = 0; index < count && result == 0; index++) {
        result = callback(mounts[index].f_mntonname, mounts[index].f_fstypename,
                          mounts[index].f_mntfromname, argument);
    }
    return result;
}
