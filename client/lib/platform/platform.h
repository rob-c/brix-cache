/*
 * client/lib/platform/platform.h - the native client's platform umbrella
 *
 * WHAT: The one header client code includes for anything host-specific. It
 *       re-exports the module PAL (platform/platform_api.h, reached through
 *       -I$(SRC)) and adds the client's own entry points and the readiness-set
 *       API the client loop is written against (epoll(7); Darwin emulates it
 *       over kqueue). No host conditional lives here: the host part comes from
 *       client/lib/platform/<host>/host.h through the same computed include
 *       the module PAL uses.
 * WHY:  tools/ci/check_platform_leak.py rejects OS macros and OS-private
 *       headers outside the host directories; client/lib/platform/<host>/ is
 *       the client's owner.
 */

#ifndef BRIX_CLIENT_PLATFORM_H
#define BRIX_CLIENT_PLATFORM_H

#include "platform/platform_api.h"
#include <stdint.h>
#include BRIX_PLAT_HOST_HEADER(host.h)

/* --- client-only PAL entry points (bodies in <host>/posix.c, <host>/mounts.c) --- */

/**
 * Unmount `path`. `lazy` asks for a deferred detach (Linux MNT_DETACH);
 * Darwin has no lazy detach and uses MNT_FORCE for the same retry.
 * @return 0, or -1 with errno
 */
int brix_plat_umount(const char *path, int lazy);

/** One mounted filesystem, as brix_plat_mounts_walk reports it. */
typedef int (*brix_plat_mount_cb)(const char *mountpoint, const char *fstype,
    const char *source, void *arg);

/**
 * Walk the mount table (Linux: /proc/self/mountinfo, or `table_path` when
 * non-NULL; Darwin: getmntinfo(3), table_path ignored) calling `cb` per
 * entry until it returns non-zero.
 * @return 0, the callback's non-zero value, or -1 with errno
 */
int brix_plat_mounts_walk(const char *table_path, brix_plat_mount_cb cb,
    void *arg);

/**
 * Two-phase idle expiry of a mount (Linux umount2(MNT_EXPIRE), root only):
 * 0 = unmounted now, -1/EAGAIN = marked and left for the next call,
 * -1/EBUSY = in use, -1/EPERM = not permitted. Darwin has no expiry and
 * always answers EPERM, so callers disable the feature the same way an
 * unprivileged Linux run does.
 */
int brix_plat_umount_expire(const char *path);

/** Upper bound on the argv brix_plat_fuse_umount_argv fills (incl. NULL). */
#define BRIX_PLAT_UMOUNT_ARGV_MAX 6

/**
 * The tier-th (0 first) command an unprivileged process runs to unmount a
 * FUSE filesystem at `path`, most specific first: Linux fusermount3 -u [-z],
 * fusermount -u [-z], umount [-l]; Darwin umount [-f] (the owner may unmount
 * its own mount and there is no lazy detach, -f is the retry).  Fills a
 * NULL-terminated argv of at most BRIX_PLAT_UMOUNT_ARGV_MAX entries whose
 * strings are static literals plus `path`.
 * @return the argv length, or 0 when there is no such tier
 */
int brix_plat_fuse_umount_argv(const char *path, int lazy, int tier,
    char **argv);

/**
 * Mount options every FUSE filesystem of ours needs on this host, as one
 * comma-separated `-o` value, or NULL when the host needs none. Darwin:
 * "noappledouble" — macFUSE otherwise mirrors each file with a "._name"
 * AppleDouble sidecar (written through CREATE/WRITE, then GETATTR'd by
 * name before the staged write is committed), which turns every write on
 * a staging filesystem into ENXIO.
 */
const char *brix_plat_fuse_host_opts(void);

/**
 * Kernel TCP statistics for the connected socket `fd`: smoothed round-trip
 * time and its variation in MICROSECONDS, plus the retransmitted-segment
 * count.  Linux reads TCP_INFO; Darwin reads TCP_CONNECTION_INFO, whose
 * equivalents are in milliseconds and are converted here so callers see one
 * unit on every host.
 * @return 0 with the three outputs set, or -1 when the host cannot report them
 */
int brix_plat_tcp_rtt(int fd, uint32_t *rtt_us, uint32_t *rttvar_us,
    uint32_t *retrans);


/**
 * 1 when the libfuse mount option `opt` (one comma-separated element, e.g.
 * "auto_unmount" or "attr_timeout=0") exists on this host's libfuse; 0 when
 * it is a Linux-only spelling the host's library would reject outright
 * (macFUSE: "auto_unmount", which it performs unconditionally anyway).
 * Mount apps drop unsupported elements before fuse_main() so one option
 * string serves every host.  Pure; exact-match on the option name.
 */
int brix_plat_fuse_opt_supported(const char *opt);

#endif /* BRIX_CLIENT_PLATFORM_H */
