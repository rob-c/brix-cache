/*
 * client/lib/platform/linux/posix.c - linux bodies only the native client needs
 *
 * WHAT: brix_plat_umount / brix_plat_umount_expire for the automounter, the
 *       unprivileged FUSE unmount command tiers and the host mount options. Every other PAL body the
 *       client calls is linked from src/platform/linux/{storage,process}_wrapper.c
 *       (client/Makefile PLATFORM_SRCS), so there is one body per host.
 * WHY:  Client code may not name the host unmount call, nor the fusermount
 *       tools, itself.
 * HOW:  Thin wrappers; the tier table is static data.
 */

#include "platform/platform.h"
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#if BRIX_PLATFORM_LINUX

#include <sys/mount.h>

int
brix_plat_umount(const char *path, int lazy)
{
    return umount2(path, lazy ? MNT_DETACH : 0);
}

int
brix_plat_umount_expire(const char *path)
{
    return umount2(path, MNT_EXPIRE);
}

int
brix_plat_fuse_umount_argv(const char *path, int lazy, int tier, char **argv)
{
    static const char *const tools[] = { "fusermount3", "fusermount", "umount" };
    int n = 0;

    if (tier < 0 || tier >= (int) (sizeof(tools) / sizeof(tools[0]))) {
        return 0;
    }
    argv[n++] = (char *) tools[tier];
    if (tier < 2) {
        argv[n++] = (char *) "-u";
        if (lazy) {
            argv[n++] = (char *) "-z";
        }
    } else if (lazy) {
        argv[n++] = (char *) "-l";
    }
    argv[n++] = (char *) path;
    argv[n] = NULL;
    return n;
}

int
brix_plat_fuse_opt_supported(const char *opt)
{
    return opt != NULL && opt[0] != '\0';   /* libfuse3 knows every spelling we emit */
}

const char *
brix_plat_fuse_host_opts(void)
{
    return NULL;   /* libfuse on Linux needs nothing beyond the caller's -o */
}


/* brix_plat_tcp_rtt lives in ../tcp_rtt.c: one body for every host, over the
 * struct/option/unit facts this host names in host_net.h. */

#endif /* BRIX_PLATFORM_LINUX */
