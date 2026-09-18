/*
 * src/platform/darwin/host_posix.h - the Darwin part of the PAL POSIX surface
 *
 * WHAT: The Linux spellings the tree is written against, provided on macOS:
 *       Linux-shaped xattr calls with the Linux errno contract, the missing
 *       constants (O_PATH, SOCK_CLOEXEC, MSG_NOSIGNAL, PR_*, CAP_*, ...) and
 *       the openat2(2) ABI the PAL emulates.
 * HOW:  Darwin's xattr calls take (position, options) extras, answer ENOATTR
 *       where Linux says ENODATA (the tree tests ENODATA), and cap names at
 *       XATTR_MAXNAMELEN (127, Linux 255) with ENAMETOOLONG. A name that
 *       cannot exist is simply absent to a reader (the WebDAV dead-property
 *       and lock probes build 170-byte names and must not turn that into a
 *       500); writes keep ENAMETOOLONG so the caller sees why. The PAL's own
 *       adapters call the host functions as `(getxattr)(...)` to bypass the
 *       call-shape macros. Sharp edge: a function-like macro also captures a
 *       struct member call spelt `driver->getxattr(...)`; write such calls as
 *       `(driver->getxattr)(...)` (a missed one fails to compile here, never
 *       silently; check_platform_leak.py rejects the unparenthesised form).
 *       Each alias keeps the behaviour the tree relied on before the PAL
 *       owned it; the semantic gaps are documented next to each.
 */

#ifndef BRIX_PLATFORM_DARWIN_HOST_POSIX_H
#define BRIX_PLATFORM_DARWIN_HOST_POSIX_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>      /* major() / minor() / makedev() */
#include <sys/xattr.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include "../openat2_abi.h"

#ifndef ENOATTR
#define ENOATTR 93   /* <sys/errno.h> hides it below __DARWIN_C_FULL */
#endif
#ifndef ENODATA
#define ENODATA ENOATTR
#endif
#ifndef XATTR_NOFOLLOW
#define XATTR_NOFOLLOW 0x0001
#endif

/* --- Linux-shaped xattr calls ------------------------------------------- */
static inline ssize_t
brix_plat_xattr_rc(ssize_t rc)
{
    if (rc < 0 && errno == ENOATTR) {
        errno = ENODATA;
    }
    return rc;
}

static inline ssize_t
brix_plat_xattr_read_rc(ssize_t rc)
{
    if (rc < 0 && (errno == ENOATTR || errno == ENAMETOOLONG)) {
        errno = ENODATA;
    }
    return rc;
}

#define getxattr(p, n, v, s)       brix_plat_xattr_read_rc((getxattr)((p), (n), (v), (s), 0, 0)) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define lgetxattr(p, n, v, s)      brix_plat_xattr_read_rc((getxattr)((p), (n), (v), (s), 0, XATTR_NOFOLLOW)) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define fgetxattr(fd, n, v, s)     brix_plat_xattr_read_rc((fgetxattr)((fd), (n), (v), (s), 0, 0)) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define setxattr(p, n, v, s, f)    ((int) brix_plat_xattr_rc((setxattr)((p), (n), (v), (s), 0, (f)))) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define lsetxattr(p, n, v, s, f)   ((int) brix_plat_xattr_rc((setxattr)((p), (n), (v), (s), 0, (f) | XATTR_NOFOLLOW))) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define fsetxattr(fd, n, v, s, f)  ((int) brix_plat_xattr_rc((fsetxattr)((fd), (n), (v), (s), 0, (f)))) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define listxattr(p, l, s)         brix_plat_xattr_read_rc((listxattr)((p), (l), (s), 0)) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define llistxattr(p, l, s)        brix_plat_xattr_read_rc((listxattr)((p), (l), (s), XATTR_NOFOLLOW)) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define flistxattr(fd, l, s)       brix_plat_xattr_read_rc((flistxattr)((fd), (l), (s), 0)) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define removexattr(p, n)          ((int) brix_plat_xattr_read_rc((removexattr)((p), (n), 0))) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define lremovexattr(p, n)         ((int) brix_plat_xattr_read_rc((removexattr)((p), (n), XATTR_NOFOLLOW))) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */
#define fremovexattr(fd, n)        ((int) brix_plat_xattr_read_rc((fremovexattr)((fd), (n), 0))) /* vfs-seam-allow: SEAM_CORRECT - PAL Darwin xattr call shape */

/* --- constants Darwin lacks ----------------------------------------------- */
#ifndef O_PATH
#define O_PATH O_RDONLY              /* no path-only handles: a real open */
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef SOCK_CLOEXEC                 /* brix_plat_accept4 / the socket helpers
                                        apply FD_CLOEXEC after the fact */
#define SOCK_CLOEXEC 0
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif
#ifndef MSG_NOSIGNAL                 /* socket helpers set SO_NOSIGPIPE instead */
#define MSG_NOSIGNAL 0
#endif
#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0
#endif
/* Linux's ENOKEY ("required key not available") has no macOS number.  It must
 * NOT be aliased to EACCES: the two mean opposite things to their callers.
 * EACCES is the ORIGIN's answer — "you may not have this" — which the cache
 * fill reports to the client as 403 and treats as definitive.  ENOKEY is OUR
 * failure to answer an auth challenge (the token endpoint was down, say),
 * which must read as 502: telling a client "you are not allowed" for an image
 * it is perfectly entitled to pull sends it chasing a permissions problem
 * that does not exist.  A value past ELAST cannot collide with a real errno. */
#ifndef ENOKEY
#define ENOKEY (ELAST + 20)
#endif
#ifndef st_mtim
#define st_mtim st_mtimespec
#endif
#ifndef PR_SET_KEEPCAPS
#define PR_SET_KEEPCAPS 8
#endif
#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif
#ifndef _LINUX_CAPABILITY_VERSION_3
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#endif
#ifndef CAP_CHOWN
#define CAP_CHOWN 0
#define CAP_DAC_OVERRIDE 1
#define CAP_DAC_READ_SEARCH 2
#define CAP_FOWNER 3
#define CAP_FSETID 4
#define CAP_SETGID 6
#define CAP_SETUID 7
#define CAP_SETPCAP 8
#define CAP_SYS_PTRACE 19
#define CAP_SYS_ADMIN 21
#define CAP_MKNOD 27
#define CAP_SETFCAP 31
#define CAP_LAST_CAP 40
#endif
struct __user_cap_header_struct {
    uint32_t version;
    int      pid;
};
struct __user_cap_data_struct {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

#endif /* BRIX_PLATFORM_DARWIN_HOST_POSIX_H */
