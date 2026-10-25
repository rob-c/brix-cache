/* FreeBSD 15+ host capabilities. Optional libraries remain build-probed.
 * Requires: compiler target selected by -DBRIX_PLATFORM_HOST=freebsd.
 */
#pragma once
#include <sys/param.h>
#if __FreeBSD_version < 1500000
#error "BriX's native FreeBSD server target requires FreeBSD 15 or newer"
#endif
#define BRIX_PLATFORM_FREEBSD 1
#define BRIX_PLATFORM_LINUX 0
#define BRIX_PLATFORM_DARWIN 0
#define BRIX_PLATFORM_WINDOWS 0
#define BRIX_HAS_IO_URING 0
#define BRIX_HAS_SECCOMP 0
#define BRIX_HAS_INOTIFY 0
/* mknod(8): non-devfs nodes cannot access devices; nodev is not a mount flag. */
#define BRIX_HAS_FUSE_NODEV 0
#define BRIX_HAS_FUNOPEN 1
#define BRIX_HAS_SPLICE 0
#define BRIX_HAS_POSIX_FADVISE 1
#define BRIX_HAS_CLONEFILE 0
#define BRIX_HAS_COPY_FILE_RANGE 1
#define BRIX_HAS_IPV6_FLOWLABEL 0
#define BRIX_HAS_TCP_INFO 1
#define BRIX_HAS_NO_NEW_PRIVS 1 /* procctl(PROC_NO_NEW_PRIVS_CTL) */
#define BRIX_HAS_WORKER_EXEC 1 /* no-new-privileges is inherited across exec */
#define BRIX_HAS_CAPABILITIES 0 /* not Linux process capabilities */
#define BRIX_HAS_FIXED_ID_BROKER 1 /* native process descriptors + Capsicum */
#define BRIX_HAS_SAVED_IDS 1
#define BRIX_PLAT_SHM_DIR "/tmp"
#define BRIX_XATTR_NAME_MAX 255u
#if defined(BRIX_HAVE_CEPH)
#define BRIX_HAS_CEPH 1
#else
#define BRIX_HAS_CEPH 0
#endif
#if defined(BRIX_HAVE_FUSE3)
#define BRIX_HAS_FUSE 1
#define BRIX_FUSE_INCLUDE <fuse3/fuse.h>
#else
#define BRIX_HAS_FUSE 0
#endif
#if defined(BRIX_KRB5_MIT) && BRIX_KRB5_MIT
#define BRIX_HAS_GSS_KRB5_IMPORT_CRED 1
#else
#define BRIX_HAS_GSS_KRB5_IMPORT_CRED 0
#endif
#define BRIX_WEAK_REF __attribute__((weak))
