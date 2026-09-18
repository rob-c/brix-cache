/*
 * src/platform/windows/host.h - Windows host description
 *
 * WHAT: Platform flags, Win32 header configuration and capability gates for
 *       a Windows build. Selected by -DBRIX_PLATFORM_HOST=windows through
 *       src/platform/platform.h. Development-grade: see README.md.
 */

#ifndef BRIX_PLATFORM_WINDOWS_HOST_H
#define BRIX_PLATFORM_WINDOWS_HOST_H

/* Host flags for the adapters' own bodies (also passed by ./config). */
#ifndef BRIX_PLATFORM_LINUX
#define BRIX_PLATFORM_LINUX 0
#endif
#ifndef BRIX_PLATFORM_DARWIN
#define BRIX_PLATFORM_DARWIN 0
#endif
#ifndef BRIX_PLATFORM_WINDOWS
#define BRIX_PLATFORM_WINDOWS 1
#endif

/* Windows 8 / Server 2012 minimum, lean headers. */
#ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0602
#endif
#ifndef WINVER
    #define WINVER 0x0602
#endif
#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN 1
#endif
#ifndef NOMINMAX
    #define NOMINMAX
#endif

/* Capability gates the portable tree may test (1 or 0 on every host). */
#define BRIX_HAS_IO_URING 0
#define BRIX_HAS_SECCOMP 0
#define BRIX_HAS_CEPH 0
#define BRIX_HAS_FUSE 0
#define BRIX_HAS_INOTIFY 0
#define BRIX_HAS_SPLICE 0
#define BRIX_HAS_POSIX_FADVISE 0
#define BRIX_HAS_CLONEFILE 0
#define BRIX_HAS_COPY_FILE_RANGE 1
#define BRIX_HAS_IPV6_FLOWLABEL 0
#define BRIX_HAS_TCP_INFO 0
#define BRIX_HAS_GSS_KRB5_IMPORT_CRED 0
#define BRIX_PLAT_SHM_DIR "/tmp"         /* stub-grade: no RAM-backed root */

/* Adapter selection. */
#define BRIX_HAS_NTFS_ADS 1
#define BRIX_HAS_IOCP 1
#define BRIX_USE_HANDLE_ABSTRACTION 1
#define BRIX_XATTR_VIA_ADS 1
#define BRIX_USE_IOCP 1
#define BRIX_USE_READDIRECTORYCHANGESW 1
#define BRIX_SECURITY_STUBS 1
#define BRIX_USE_TRANSMITFILE 1
#define BRIX_SECURITY_INIT_STUB 1
#define BRIX_SECURITY_ENTER_STUB 1

/* An optional symbol a binary may be linked without (development-grade). */
#ifndef BRIX_WEAK_REF
#define BRIX_WEAK_REF __attribute__((weak))
#endif

#endif /* BRIX_PLATFORM_WINDOWS_HOST_H */
