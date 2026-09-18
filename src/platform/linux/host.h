/*
 * src/platform/linux/host.h - Linux host description
 *
 * WHAT: Platform flags and capability gates for a Linux build. Selected by
 *       -DBRIX_PLATFORM_HOST=linux through src/platform/platform.h.
 * HOW:  Optional kernel/library features come from the build probes
 *       (BRIX_HAVE_LIBURING, BRIX_HAVE_SECCOMP, BRIX_HAVE_CEPH, BRIX_HAVE_FUSE3).
 */

#ifndef BRIX_PLATFORM_LINUX_HOST_H
#define BRIX_PLATFORM_LINUX_HOST_H

/* Host flags for the adapters' own bodies (also passed by ./config). */
#ifndef BRIX_PLATFORM_LINUX
#define BRIX_PLATFORM_LINUX 1
#endif
#ifndef BRIX_PLATFORM_DARWIN
#define BRIX_PLATFORM_DARWIN 0
#endif
#ifndef BRIX_PLATFORM_WINDOWS
#define BRIX_PLATFORM_WINDOWS 0
#endif

/* Capability gates the portable tree may test (1 or 0 on every host). */
#if defined(BRIX_HAVE_LIBURING)
    #define BRIX_HAS_IO_URING 1
#else
    #define BRIX_HAS_IO_URING 0
#endif
#if defined(BRIX_HAVE_SECCOMP)
    #define BRIX_HAS_SECCOMP 1
#else
    #define BRIX_HAS_SECCOMP 0
#endif
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
#define BRIX_HAS_INOTIFY 1
#define BRIX_HAS_SPLICE 1
#define BRIX_HAS_POSIX_FADVISE 1
#define BRIX_HAS_CLONEFILE 0
#define BRIX_HAS_COPY_FILE_RANGE 1
#define BRIX_HAS_IPV6_FLOWLABEL 1        /* IPV6_FLOWLABEL_MGR socket option */
#define BRIX_HAS_TCP_INFO 1              /* TCP_INFO byte/RTT counters */
#define BRIX_HAS_GSS_KRB5_IMPORT_CRED 1  /* MIT gss_krb5_import_cred */
#define BRIX_PLAT_SHM_DIR "/dev/shm"     /* RAM-backed sticky scratch root */

/* An optional symbol a binary may be linked without: ELF resolves an
 * undefined weak function to NULL. */
#ifndef BRIX_WEAK_REF
#define BRIX_WEAK_REF __attribute__((weak))
#endif

#endif /* BRIX_PLATFORM_LINUX_HOST_H */
