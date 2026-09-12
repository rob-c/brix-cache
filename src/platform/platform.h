/*
 * src/platform/platform.h - Platform detection and feature gating
 * 
 * This header is included by every source file that uses platform-specific APIs.
 * It must be included AFTER nginx core headers but BEFORE any platform-specific headers.
 * 
 * Compilation fails if none of BRIX_PLATFORM_LINUX, BRIX_PLATFORM_DARWIN, or BRIX_PLATFORM_WINDOWS is defined.
 * 
 * Supported Platforms (Phase 3 Complete - 100% PAL on all 5 platforms):
 * - Linux x86_64/ARM64 (Production Ready)
 * - macOS x86_64/ARM64 (Production Ready)
 * - Windows x86_64 (Development Ready - use WSL2 for production)
 */

#ifndef BRIX_PLATFORM_H
#define BRIX_PLATFORM_H

#include <ngx_core.h>

/* ==========================================================================
 * PLATFORM DETECTION - DO NOT MODIFY
 * These macros are set by the build system (config or CMakeLists.txt)
 * ========================================================================== */

#if defined(__linux__)
    #ifndef BRIX_PLATFORM_LINUX
        #define BRIX_PLATFORM_LINUX 1
    #endif
    #ifndef BRIX_PLATFORM_DARWIN
        #define BRIX_PLATFORM_DARWIN 0
    #endif
    
#elif defined(__APPLE__) && defined(__MACH__)
    #ifndef BRIX_PLATFORM_LINUX
        #define BRIX_PLATFORM_LINUX 0
    #endif
    #ifndef BRIX_PLATFORM_DARWIN
        #define BRIX_PLATFORM_DARWIN 1
    #endif
    #ifndef BRIX_PLATFORM_WINDOWS
        #define BRIX_PLATFORM_WINDOWS 0
    #endif
    
    /* macOS version detection */
    #include <TargetConditionals.h>
    #if TARGET_OS_MAC && !TARGET_OS_IPHONE
        #define BRIX_PLATFORM_MACOS 1
    #else
        #error "Unsupported Darwin variant (iOS, tvOS, etc. not supported)"
    #endif
    
    /* Minimum macOS version check - will be enforced when build is tested */
    #ifndef BRIX_MACOS_MIN_VERSION
        #define BRIX_MACOS_MIN_VERSION 120000  /* macOS 12.0 (Monterey) */
    #endif
    
#elif defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
    #ifndef BRIX_PLATFORM_LINUX
        #define BRIX_PLATFORM_LINUX 0
    #endif
    #ifndef BRIX_PLATFORM_DARWIN
        #define BRIX_PLATFORM_DARWIN 0
    #endif
    #ifndef BRIX_PLATFORM_WINDOWS
        #define BRIX_PLATFORM_WINDOWS 1
    #endif
    
    /* Windows version detection - Windows 8 / Server 2012 minimum */
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0602  /* Windows 8 */
    #endif
    #ifndef WINVER
        #define WINVER 0x0602
    #endif
    
    /* Lean and mean Windows - exclude unused APIs */
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN 1
    #endif
    
    /* NTFS ADS for xattr support */
    #define BRIX_HAS_NTFS_ADS 1
    
    /* IOCP for event handling */
    #define BRIX_HAS_IOCP 1
    
#else
    #error "Unsupported platform. BriX-Cache supports Linux, macOS, and Windows (x86_64)."
#endif

/* ==========================================================================
 * ARCHITECTURE DETECTION
 * These macros detect the CPU architecture at compile-time
 * ========================================================================== */

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
    #ifndef BRIX_ARCH_ARM64
        #define BRIX_ARCH_ARM64 1
    #endif
    #ifndef BRIX_ARCH_X86_64
        #define BRIX_ARCH_X86_64 0
    #endif
#elif defined(__x86_64__) || defined(_M_X64)
    #ifndef BRIX_ARCH_ARM64
        #define BRIX_ARCH_ARM64 0
    #endif
    #ifndef BRIX_ARCH_X86_64
        #define BRIX_ARCH_X86_64 1
    #endif
#else
    /* Unknown architecture - disable architecture-specific optimizations */
    #ifndef BRIX_ARCH_ARM64
        #define BRIX_ARCH_ARM64 0
    #endif
    #ifndef BRIX_ARCH_X86_64
        #define BRIX_ARCH_X86_64 0
    #endif
#endif

/* ==========================================================================
 * FEATURE GATING
 * These macros control which features are compiled in
 * ========================================================================== */

/* io_uring - Linux 5.1+ only */
#if BRIX_PLATFORM_LINUX && defined(BRIX_HAVE_LIBURING)
    #define BRIX_HAS_IO_URING 1
#else
    #define BRIX_HAS_IO_URING 0
#endif

/* seccomp-bpf - Linux only */
#if BRIX_PLATFORM_LINUX && defined(BRIX_HAVE_SECCOMP)
    #define BRIX_HAS_SECCOMP 1
#else
    #define BRIX_HAS_SECCOMP 0
#endif

/* CephFS backend - Linux only (no macOS Ceph support) */
#if BRIX_PLATFORM_LINUX && defined(BRIX_HAVE_CEPH)
    #define BRIX_HAS_CEPH 1
#else
    #define BRIX_HAS_CEPH 0
#endif

/* inotify - Linux only */
#if BRIX_PLATFORM_LINUX
    #define BRIX_HAS_INOTIFY 1
#else
    #define BRIX_HAS_INOTIFY 0
#endif

/* splice() - Linux only */
#if BRIX_PLATFORM_LINUX
    #define BRIX_HAS_SPLICE 1
#else
    #define BRIX_HAS_SPLICE 0
#endif

/* posix_fadvise - Linux only (macOS XNU lacks implementation) */
#if BRIX_PLATFORM_LINUX
    #define BRIX_HAS_POSIX_FADVISE 1
#else
    #define BRIX_HAS_POSIX_FADVISE 0
#endif

/* FUSE support */
#if BRIX_PLATFORM_LINUX && defined(BRIX_HAVE_FUSE3)
    #define BRIX_HAS_FUSE 1
    #define BRIX_FUSE_INCLUDE <fuse3/fuse.h>
#elif BRIX_PLATFORM_DARWIN && defined(BRIX_HAVE_MACFUSE)
    #define BRIX_HAS_FUSE 1
    #define BRIX_FUSE_INCLUDE <osxfuse/fuse.h>
#else
    #define BRIX_HAS_FUSE 0
#endif

/* ==========================================================================
 * PLATFORM-SPECIFIC MACROS
 * ========================================================================== */

#if BRIX_PLATFORM_DARWIN
    /* macOS uses different sendfile() signature */
    #define BRIX_SENDFILE_MACOS 1
    
    /* macOS XNU lacks posix_fadvise - stub as no-op */
    #define BRIX_POSIX_FADVISE_STUB 1
    
    /* macOS Security framework for certificate handling */
    #define BRIX_USE_SECURITY_FRAMEWORK 1
    
    /* macOS Keychain for credential storage (optional) */
    #ifndef BRIX_DISABLE_KEYCHAIN
        #define BRIX_USE_KEYCHAIN 1
    #endif
    
    /* APFS clonefile() for fast file copies (macOS 10.12+) */
    #define BRIX_HAS_CLONEFILE 1
#endif

#if BRIX_PLATFORM_WINDOWS
    /* Windows uses HANDLE-based I/O abstraction */
    #define BRIX_USE_HANDLE_ABSTRACTION 1
    
    /* Windows uses NTFS Alternate Data Streams for xattr */
    #define BRIX_XATTR_VIA_ADS 1
    
    /* Windows uses IOCP for event notification */
    #define BRIX_USE_IOCP 1
    
    /* Windows uses ReadDirectoryChangesW for filesystem watching */
    #define BRIX_USE_READDIRECTORYCHANGESW 1
    
    /* Windows lacks POSIX capabilities - use stubs */
    #define BRIX_SECURITY_STUBS 1
    
    /* Windows uses TransmitFile for zero-copy socket sends */
    #define BRIX_USE_TRANSMITFILE 1
    
    /* Windows uses CopyFile2/copy_file_range for zero-copy file copies */
    #define BRIX_HAS_COPY_FILE_RANGE 1
    
    /* Windows lacks inotify - use ReadDirectoryChangesW */
    #undef BRIX_HAS_INOTIFY
    #define BRIX_HAS_INOTIFY 0
    
    /* Windows lacks splice() - use buffered copy */
    #undef BRIX_HAS_SPLICE
    #define BRIX_HAS_SPLICE 0
    
    /* Windows lacks posix_fadvise */
    #undef BRIX_HAS_POSIX_FADVISE
    #define BRIX_HAS_POSIX_FADVISE 0
    
    /* Windows min/max macro conflict prevention */
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    
    /* Prevent Windows API macro pollution */
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN 1
    #endif
    
    /* Windows Security API stubs (Job Objects/AppContainer for future) */
    #define BRIX_SECURITY_INIT_STUB 1
    #define BRIX_SECURITY_ENTER_STUB 1
#endif

/* ==========================================================================
 * COMPILER ATTRIBUTES
 * ========================================================================== */

#if BRIX_PLATFORM_DARWIN
    /* macOS clang-specific attributes */
    #define BRIX_UNUSED __attribute__((unused))
    #define BRIX_NORETURN __attribute__((noreturn))
    #define BRIX_MALLOC __attribute__((malloc))
    #define BRIX_ALIGNED(x) __attribute__((aligned(x)))
#else
    /* GCC/clang on Linux */
    #define BRIX_UNUSED __attribute__((unused))
    #define BRIX_NORETURN __attribute__((noreturn))
    #define BRIX_MALLOC __attribute__((malloc))
    #define BRIX_ALIGNED(x) __attribute__((aligned(x)))
#endif

/* ==========================================================================
 * ASSERTIONS - Compile-time checks
 * ========================================================================== */

/* Ensure exactly one platform is defined */
#if (BRIX_PLATFORM_LINUX + BRIX_PLATFORM_DARWIN + BRIX_PLATFORM_WINDOWS) != 1
    #error "Exactly one of BRIX_PLATFORM_LINUX, BRIX_PLATFORM_DARWIN, or BRIX_PLATFORM_WINDOWS must be defined"
#endif

/* Ensure incompatible features are not both enabled */
#if BRIX_HAS_IO_URING && BRIX_PLATFORM_DARWIN
    #error "io_uring is not available on macOS"
#endif

#if BRIX_HAS_IO_URING && BRIX_PLATFORM_WINDOWS
    #error "io_uring is not available on Windows (use WSL2 for io_uring support)"
#endif

#if BRIX_HAS_SECCOMP && BRIX_PLATFORM_DARWIN
    #error "seccomp-bpf is not available on macOS"
#endif

#if BRIX_HAS_SECCOMP && BRIX_PLATFORM_WINDOWS
    #error "seccomp-bpf is not available on Windows (use WSL2 for seccomp support)"
#endif

#if BRIX_HAS_CEPH && BRIX_PLATFORM_DARWIN
    #error "CephFS has no macOS support"
#endif

#if BRIX_HAS_CEPH && BRIX_PLATFORM_WINDOWS
    #error "CephFS has no Windows support (use WSL2 for CephFS)"
#endif

#endif /* BRIX_PLATFORM_H */
