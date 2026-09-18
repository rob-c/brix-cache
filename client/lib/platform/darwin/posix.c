/*
 * client/lib/platform/darwin/posix.c - darwin bodies only the native client needs
 *
 * WHAT: brix_plat_umount / brix_plat_umount_expire for the automounter, the
 *       unprivileged FUSE unmount command tier and the macFUSE mount options. Every other PAL body the
 *       client calls is linked from src/platform/darwin/{storage,process}_wrapper.c
 *       (client/Makefile PLATFORM_SRCS), so there is one body per host.
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

int
brix_plat_umount_expire(const char *path)
{
    (void) path;
    errno = EPERM;   /* no idle expiry: callers disable it as unprivileged Linux does */
    return -1;
}

int
brix_plat_fuse_umount_argv(const char *path, int lazy, int tier, char **argv)
{
    int n = 0;

    if (tier != 0) {
        return 0;
    }
    argv[n++] = (char *) "umount";
    if (lazy) {
        argv[n++] = (char *) "-f";
    }
    argv[n++] = (char *) path;
    argv[n] = NULL;
    return n;
}

/* macFUSE unmounts when the daemon exits and rejects the Linux libfuse
 * spelling that asks for exactly that ("fuse: unknown option(s): `-o
 * auto_unmount'"), so the element is dropped rather than passed through. */
int
brix_plat_fuse_opt_supported(const char *opt)
{
    if (opt == NULL || opt[0] == '\0') {
        return 0;
    }
    return strcmp(opt, "auto_unmount") != 0;
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


/* Darwin has no TCP_INFO; TCP_CONNECTION_INFO carries the same facts, with
 * the smoothed RTT and its variation in MILLISECONDS. */
int
brix_plat_tcp_rtt(int fd, uint32_t *rtt_us, uint32_t *rttvar_us,
    uint32_t *retrans)
{
    struct tcp_connection_info ti;
    socklen_t                  len = sizeof(ti);

    memset(&ti, 0, sizeof(ti));
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &ti, &len) != 0) {
        return -1;
    }
    *rtt_us    = (uint32_t) ti.tcpi_srtt * 1000u;
    *rttvar_us = (uint32_t) ti.tcpi_rttvar * 1000u;
    *retrans   = (uint32_t) ti.tcpi_txretransmitpackets;
    return 0;
}

#endif /* BRIX_PLATFORM_DARWIN */
