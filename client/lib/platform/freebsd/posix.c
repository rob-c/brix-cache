/* Native FreeBSD FUSE lifecycle operations for the client PAL. */
#include "platform/platform.h"
#include <sys/mount.h>

/* WHAT: Unmount the supplied filesystem. WHY: Keep native calls in the PAL.
 * HOW: Map the explicit force retry; FreeBSD has no Linux lazy-detach contract. */
int brix_plat_umount(const char *path, int force)
{ return unmount(path, force ? MNT_FORCE : 0); }

/* WHAT: Return no unrequested host options. WHY: No AppleDouble workaround is
 * needed on FreeBSD. HOW: Leave caller-owned mount policy unchanged. */
const char *brix_plat_fuse_host_opts(void) { return NULL; }
