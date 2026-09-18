/*
 * src/platform/darwin/host.h - macOS host description
 *
 * WHAT: Platform flags and capability gates for a Darwin build. Selected by
 *       -DBRIX_PLATFORM_HOST=darwin through src/platform/platform.h.
 * HOW:  Only macOS proper is supported (no iOS/tvOS variants); macFUSE comes
 *       from the BRIX_HAVE_MACFUSE build probe. io_uring, seccomp and CephFS
 *       do not exist here, so their gates are 0 unconditionally.
 */

#ifndef BRIX_PLATFORM_DARWIN_HOST_H
#define BRIX_PLATFORM_DARWIN_HOST_H

#include <TargetConditionals.h>
#if !TARGET_OS_MAC || TARGET_OS_IPHONE
    #error "Unsupported Darwin variant (iOS, tvOS, etc. not supported)"
#endif

/* Host flags for the adapters' own bodies (also passed by ./config). */
#ifndef BRIX_PLATFORM_LINUX
#define BRIX_PLATFORM_LINUX 0
#endif
#ifndef BRIX_PLATFORM_DARWIN
#define BRIX_PLATFORM_DARWIN 1
#endif
#ifndef BRIX_PLATFORM_WINDOWS
#define BRIX_PLATFORM_WINDOWS 0
#endif

/* Minimum macOS version check - enforced where the build is tested. */
#ifndef BRIX_MACOS_MIN_VERSION
    #define BRIX_MACOS_MIN_VERSION 120000  /* macOS 12.0 (Monterey) */
#endif
#define BRIX_PLATFORM_MACOS 1

/* Capability gates the portable tree may test (1 or 0 on every host). */
#define BRIX_HAS_IO_URING 0
#define BRIX_HAS_SECCOMP 0
#define BRIX_HAS_CEPH 0
#if defined(BRIX_HAVE_MACFUSE)
    #define BRIX_HAS_FUSE 1
    #define BRIX_FUSE_INCLUDE <osxfuse/fuse.h>
#else
    #define BRIX_HAS_FUSE 0
#endif
#define BRIX_HAS_INOTIFY 0
#define BRIX_HAS_SPLICE 0
#define BRIX_HAS_POSIX_FADVISE 0
#define BRIX_HAS_CLONEFILE 1
#define BRIX_HAS_COPY_FILE_RANGE 0
#define BRIX_HAS_IPV6_FLOWLABEL 0
#define BRIX_HAS_TCP_INFO 0
/* gss_krb5_import_cred is an MIT extension.  Apple's system Kerberos is
 * Heimdal (no import call), but a build against the Homebrew MIT keg has it:
 * the configure script sets BRIX_KRB5_MIT from `krb5-config --vendor`. */
#if defined(BRIX_KRB5_MIT) && BRIX_KRB5_MIT
#define BRIX_HAS_GSS_KRB5_IMPORT_CRED 1  /* MIT keg: forwarded TGT capture works */
#else
#define BRIX_HAS_GSS_KRB5_IMPORT_CRED 0  /* Heimdal lacks the import call */
#endif
#define BRIX_PLAT_SHM_DIR "/tmp"         /* no /dev/shm: sticky, disk-backed */

/* Adapter selection recorded for the host README and the native fixtures. */
#define BRIX_SENDFILE_MACOS 1
#define BRIX_POSIX_FADVISE_STUB 1
#define BRIX_USE_SECURITY_FRAMEWORK 1
#ifndef BRIX_DISABLE_KEYCHAIN
    #define BRIX_USE_KEYCHAIN 1
#endif

/* An optional symbol a binary may be linked without: Mach-O's ld64 needs
 * weak_import (and the link may still have to allow the symbol undefined,
 * -Wl,-U,_name). */
#ifndef BRIX_WEAK_REF
#define BRIX_WEAK_REF __attribute__((weak_import))
#endif

#endif /* BRIX_PLATFORM_DARWIN_HOST_H */
