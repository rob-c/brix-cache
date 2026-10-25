/*
 * client/lib/platform/darwin/posix.c - darwin bodies only the native client needs
 *
 * WHAT: Native unmount and macFUSE mount options. Shared BSD FUSE policy lives
 *       in ../fuse_bsd.c; other PAL bodies are linked from the module's
 *       src/platform/darwin/{storage,process}_wrapper.c via PLATFORM_SRCS.
 * WHY:  Client code may not name the host unmount call itself.
 * HOW:  unmount(2) for the syscall; macFUSE has no fusermount, the owner of
 *       a mount unmounts it with plain umount(8), and there is no lazy detach
 *       or MNT_EXPIRE two-phase expiry on this kernel.
 */

#include "platform/platform.h"
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#if BRIX_PLATFORM_DARWIN

#include <errno.h>
#include <string.h>
#include <sys/mount.h>

int
brix_plat_umount(const char *path, int lazy)
{
    /* no lazy detach on Darwin: MNT_FORCE is the closest for the EBUSY retry */
    return unmount(path, lazy ? MNT_FORCE : 0);
}

const char *
brix_plat_fuse_host_opts(void)
{
    /* No "._name" AppleDouble sidecars: they are created and written through
     * the filesystem and then looked up by name before a staged write lands,
     * which fails every write with ENXIO on a filesystem that commits on
     * close. Extended attributes still go through the driver's own xattr ops. */
    return "noappledouble";
}


/* brix_plat_tcp_rtt lives in ../tcp_rtt.c: one body for every host, over the
 * struct/option/unit facts this host names in host_net.h. */

#endif /* BRIX_PLATFORM_DARWIN */
