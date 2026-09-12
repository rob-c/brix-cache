/*
 * src/platform/platform_compat.h - Compatibility layer for migrating existing code
 * 
 * This header provides drop-in replacements for common platform-specific calls,
 * making it easier to migrate existing code to use the platform API.
 * 
 * Usage: Include this header in files that currently use direct syscalls,
 * then gradually migrate to explicit platform API calls.
 */

#ifndef BRIX_PLATFORM_COMPAT_H
#define BRIX_PLATFORM_COMPAT_H

#include "platform.h"
#include "platform_api.h"

/* ==========================================================================
 * FILE I/O COMPATIBILITY MACROS
 * 
 * These macros provide drop-in replacements for common syscalls.
 * They automatically route to the platform-specific implementation.
 * ========================================================================== */

/* posix_fadvise replacement */
#if BRIX_PLATFORM_LINUX
    #define brix_fadvise(fd, offset, len, advice) \
        posix_fadvise((fd), (offset), (len), (advice))
#else
    #define brix_fadvise(fd, offset, len, advice) \
        brix_platform_fadvise((fd), (offset), (len), (advice))
#endif

/* fdatasync replacement - macOS uses F_FULLFSYNC */
#if BRIX_PLATFORM_LINUX
    #define brix_fsync_data(fd) fdatasync(fd)
#else
    #define brix_fsync_data(fd) brix_platform_fsync_data(fd)
#endif

/* syncfs replacement - macOS uses sync() */
#if BRIX_PLATFORM_LINUX && defined(__NR_syncfs)
    #include <sys/syscall.h>
    #define brix_sync_tree(dirfd) syscall(__NR_syncfs, (dirfd))
#else
    #define brix_sync_tree(dirfd) brix_platform_sync_tree(dirfd)
#endif

/* sendfile replacement - handles signature differences */
#define brix_sendfile(out_fd, in_fd, offset, count) \
    brix_platform_sendfile((out_fd), (in_fd), (offset), (count))

/* splice replacement - macOS uses buffered copy */
#if BRIX_PLATFORM_LINUX
    #define brix_splice(in_fd, out_fd, nbytes, flags) \
        splice((in_fd), NULL, (out_fd), NULL, (nbytes), (flags))
#else
    #define brix_splice(in_fd, out_fd, nbytes, flags) \
        brix_platform_splice((in_fd), (out_fd), (nbytes), (flags))
#endif

/* clonefile replacement - Linux stub, macOS native */
#if BRIX_PLATFORM_DARWIN
    #define brix_clonefile(src, dst) clonefile((src), (dst), 0)
#else
    #define brix_clonefile(src, dst) brix_platform_clonefile((src), (dst))
#endif

/* ==========================================================================
 * EVENT MONITORING COMPATIBILITY
 * 
 * These provide unified event monitoring across platforms.
 * ========================================================================== */

/* Event fd type - works with both epoll and kqueue */
typedef int brix_event_fd_t;

#define BRIX_EVENT_FD_INVALID (-1)

/* Initialize event monitoring */
static inline brix_event_fd_t
brix_compat_event_init(void)
{
    return brix_platform_event_init();
}

/* Close event monitoring */
static inline void
brix_compat_event_close(brix_event_fd_t event_fd)
{
    if (event_fd != BRIX_EVENT_FD_INVALID) {
        brix_platform_event_close(event_fd);
    }
}

/* ==========================================================================
 * FILESYSTEM MONITORING COMPATIBILITY
 * ========================================================================== */

/* Watcher type alias */
typedef brix_fs_watcher_t *brix_fs_watcher_handle;

#define BRIX_FS_WATCHER_INVALID NULL

/* ==========================================================================
 * SECURITY COMPATIBILITY
 * ========================================================================== */

/* Security profile names */
#define BRIX_SECURITY_PROFILE_OFF      "off"
#define BRIX_SECURITY_PROFILE_AUDIT    "audit"
#define BRIX_SECURITY_PROFILE_DEFAULT  "default"
#define BRIX_SECURITY_PROFILE_ENFORCE  "enforce"

/* ==========================================================================
 * MIGRATION GUIDANCE
 * 
 * To migrate existing code:
 * 
 * 1. Replace direct syscalls with brix_* equivalents:
 *    OLD: posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
 *    NEW: brix_fadvise(fd, 0, 0, BRIX_FADV_SEQUENTIAL);
 * 
 * 2. Replace platform-specific event handling:
 *    OLD: #if defined(__linux__)
 *             epfd = epoll_create1(EPOLL_CLOEXEC);
 *         #else
 *             kq = kqueue();
 *         #endif
 *    NEW: event_fd = brix_compat_event_init();
 * 
 * 3. Replace direct sendfile calls:
 *    OLD: sendfile(out_fd, in_fd, &offset, count);
 *    NEW: brix_sendfile(out_fd, in_fd, &offset, count);
 * 
 * 4. For new code, always use the explicit platform API:
 *    brix_platform_fadvise(), brix_platform_event_init(), etc.
 * ========================================================================== */

#endif /* BRIX_PLATFORM_COMPAT_H */
