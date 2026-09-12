/*
 * src/platform/windows/win32_compat.h - Windows compatibility layer
 * 
 * Provides type definitions, macros, and helper functions for Windows PAL.
 * This header is included by all Windows PAL implementation files.
 */

#ifndef BRIX_WIN32_COMPAT_H
#define BRIX_WIN32_COMPAT_H

/* Windows version requirement: Windows 8 / Server 2012 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <bcrypt.h>
#include <io.h>
#include <fcntl.h>
#include <direct.h>
#include <sys/stat.h>
#include <process.h>

/* Include PAL API */
#include "../platform_api.h"

/* Include handle abstraction layer */
#include "handle_abstraction.h"

/* ==========================================================================
 * TYPE DEFINITIONS
 * ========================================================================== */

/*
 * Handle abstraction: Windows uses HANDLE, POSIX uses file descriptors
 * This union allows seamless conversion between the two
 */
typedef union {
    int fd;
    HANDLE handle;
    SOCKET socket;
} brix_win32_handle_t;

/* Handle types for proper cleanup */
#define BRIX_WIN32_HANDLE_INVALID   -1
#define BRIX_WIN32_HANDLE_FILE      0
#define BRIX_WIN32_HANDLE_SOCKET    1
#define BRIX_WIN32_HANDLE_PIPE      2
#define BRIX_WIN32_HANDLE_EVENT     3

/* ==========================================================================
 * ERROR HANDLING
 * ========================================================================== */

/* Convert Windows error to errno */
static inline void brix_win32_set_errno(DWORD error)
{
    switch (error) {
        case ERROR_SUCCESS:
            errno = 0;
            break;
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
            errno = ENOENT;
            break;
        case ERROR_ACCESS_DENIED:
        case ERROR_SHARING_VIOLATION:
            errno = EACCES;
            break;
        case ERROR_OUTOFMEMORY:
            errno = ENOMEM;
            break;
        case ERROR_FILE_EXISTS:
        case ERROR_ALREADY_EXISTS:
            errno = EEXIST;
            break;
        case ERROR_NO_MORE_FILES:
            errno = ENOENT;
            break;
        case ERROR_HANDLE_EOF:
            errno = 0;  /* Not an error, just EOF */
            break;
        case ERROR_PIPE_BUSY:
            errno = EAGAIN;
            break;
        case ERROR_IO_PENDING:
            errno = EINPROGRESS;
            break;
        case WSAEWOULDBLOCK:
            errno = EAGAIN;
            break;
        case WSAECONNRESET:
            errno = ECONNRESET;
            break;
        case WSAENOTSOCK:
            errno = ENOTSOCK;
            break;
        default:
            errno = EINVAL;
            break;
    }
}

/* Get last Windows error */
static inline DWORD brix_win32_last_error(void)
{
    return GetLastError();
}

/* ==========================================================================
 * PATH UTILITIES
 * ========================================================================== */

/* Convert forward slashes to backslashes */
static inline void brix_win32_normalize_path(char *path)
{
    while (*path) {
        if (*path == '/') {
            *path = '\\';
        }
        path++;
    }
}

/* Check if path is absolute */
static inline int brix_win32_is_absolute_path(const char *path)
{
    /* Check for drive letter (C:\) */
    if (isalpha((unsigned char)path[0]) && path[1] == ':') {
        return 1;
    }
    
    /* Check for UNC path (\\server\share) */
    if (path[0] == '\\' && path[1] == '\\') {
        return 1;
    }
    
    return 0;
}

/* ==========================================================================
 * FILE DESCRIPTOR OPERATIONS
 * ========================================================================== */

/* See handle_abstraction.h for brix_win32_fd_to_handle(), brix_win32_close_handle(), etc. */

/* ==========================================================================
 * MISSING POSIX FUNCTIONS
 * ========================================================================== */

/* Windows doesn't have these POSIX functions - provide replacements */

#ifndef HAVE_STRDUP
static inline char *brix_win32_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *dup = (char *)malloc(len);
    if (dup) {
        memcpy(dup, s, len);
    }
    return dup;
}
#define strdup brix_win32_strdup
#endif

#ifndef HAVE_SNPRINTF
#define snprintf _snprintf
#endif

#ifndef HAVE_VSNPRINTF
#define vsnprintf _vsnprintf
#endif

#ifndef HAVE_STRTOK_R
#define strtok_r strtok_s
#endif

#ifndef HAVE_LOCALTIME_R
#define localtime_r localtime_s
#endif

#ifndef HAVE_GMTIME_R
#define gmtime_r gmtime_s
#endif

/* ==========================================================================
 * STAT COMPATIBILITY
 * ========================================================================== */

/* Windows stat structure is compatible, but some fields differ */
#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

#ifndef S_ISLNK
/* Windows doesn't have symlinks in the same way (has junctions/reparse points) */
#define S_ISLNK(m) 0
#endif

/* ==========================================================================
 * ATOMIC OPERATIONS
 * ========================================================================== */

/* Windows has Interlocked functions for atomics */
#define brix_win32_atomic_inc(ptr) InterlockedIncrement((LONG *)(ptr))
#define brix_win32_atomic_dec(ptr) InterlockedDecrement((LONG *)(ptr))
#define brix_win32_atomic_add(ptr, val) InterlockedExchangeAdd((LONG *)(ptr), (val))
#define brix_win32_atomic_set(ptr, val) InterlockedExchange((LONG *)(ptr), (val))

/* ==========================================================================
 * ALLOCATION
 * ========================================================================== */

/* Windows has _aligned_malloc for aligned allocation */
static inline void *brix_win32_aligned_malloc(size_t size, size_t alignment)
{
    return _aligned_malloc(size, alignment);
}

static inline void brix_win32_aligned_free(void *ptr)
{
    _aligned_free(ptr);
}

#define brix_aligned_malloc(size, alignment) brix_win32_aligned_malloc((size), (alignment))
#define brix_aligned_free(ptr) brix_win32_aligned_free(ptr)

/* ==========================================================================
 * PLATFORM DETECTION
 * ========================================================================== */

static inline int brix_win32_is_server(void)
{
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;
    
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.wProductType = VER_NT_SERVER;
    
    VER_SET_CONDITION(dwlConditionMask, VER_PRODUCT_TYPE, VER_EQUAL);
    
    return VerifyVersionInfo(&osvi, VER_PRODUCT_TYPE, dwlConditionMask);
}

static inline int brix_win32_version_major(void)
{
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO *)&osvi);
    return osvi.dwMajorVersion;
}

#endif /* BRIX_WIN32_COMPAT_H */
