/*
 * src/platform/windows/handle_abstraction.h - Windows HANDLE/fd abstraction header
 * 
 * Status: 🚧 IMPLEMENTATION COMPLETE
 * 
 * Provides thread-safe mapping between POSIX file descriptors and Windows HANDLEs.
 * Include this header in Windows PAL implementation files that need fd/HANDLE conversion.
 */

#ifndef BRIX_WIN32_HANDLE_ABSTRACTION_H
#define BRIX_WIN32_HANDLE_ABSTRACTION_H

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include <winsock2.h>
#include <windows.h>
#include <io.h>

/* ==========================================================================
 * HANDLE TYPE ENUMERATION
 * ========================================================================== */

/**
 * Handle type for proper cleanup
 * 
 * Different handle types require different cleanup operations:
 * - FD_FILE: Regular file handles (CloseHandle)
 * - FD_SOCKET: Winsock sockets (closesocket)
 * - FD_PIPE: Pipe handles (CloseHandle)
 * - FD_EVENT: Event objects, semaphores, etc. (CloseHandle)
 */
typedef enum {
    FD_UNUSED = 0,
    FD_FILE,
    FD_SOCKET,
    FD_PIPE,
    FD_EVENT
} brix_win32_fd_type_t;

/* ==========================================================================
 * HANDLE REGISTRATION API
 * ========================================================================== */

/**
 * Register a new HANDLE and allocate an fd
 * 
 * @param handle Windows HANDLE to register
 * @param type Handle type (FD_FILE, FD_SOCKET, etc.)
 * @param name Optional debug name (can be NULL)
 * @return New file descriptor (>= 0), or -1 on error (errno set)
 */
int brix_win32_register_handle(HANDLE handle, brix_win32_fd_type_t type, const char *name);

/**
 * Register a SOCKET and allocate an fd
 * 
 * @param socket Winsock SOCKET to register
 * @return New file descriptor (>= 0), or -1 on error (errno set)
 */
int brix_win32_register_socket(SOCKET socket);

/* ==========================================================================
 * HANDLE CONVERSION API
 * ========================================================================== */

/**
 * Convert file descriptor to HANDLE
 * 
 * @param fd File descriptor
 * @return HANDLE on success, NULL on error (errno set)
 */
HANDLE brix_win32_fd_to_handle(int fd);

/**
 * Convert file descriptor to SOCKET
 * 
 * @param fd File descriptor (must be FD_SOCKET type)
 * @return SOCKET on success, INVALID_SOCKET on error (errno set)
 */
SOCKET brix_win32_fd_to_socket(int fd);

/**
 * Get handle type
 * 
 * @param fd File descriptor
 * @return Handle type, or FD_UNUSED on error
 */
brix_win32_fd_type_t brix_win32_get_fd_type(int fd);

/* ==========================================================================
 * HANDLE CLEANUP API
 * ========================================================================== */

/**
 * Close a file descriptor and release its HANDLE
 * 
 * @param fd File descriptor to close
 * @return 0 on success, -1 on error (errno set)
 */
int brix_win32_close_handle(int fd);

/**
 * Duplicate a file descriptor (increment refcount)
 * 
 * @param fd File descriptor to duplicate
 * @return New fd (same as input), or -1 on error (errno set)
 */
int brix_win32_dup_fd(int fd);

/**
 * Get debug name for a file descriptor
 * 
 * @param fd File descriptor
 * @return Debug name, or NULL if not set
 */
const char *brix_win32_get_fd_name(int fd);

/* ==========================================================================
 * REGISTRY MANAGEMENT API
 * ========================================================================== */

/**
 * Get registry statistics
 * 
 * @param capacity Output: total capacity (can be NULL)
 * @param used Output: number of active handles (can be NULL)
 * @param next_fd Output: next fd to be allocated (can be NULL)
 */
void brix_win32_get_registry_stats(size_t *capacity, size_t *used, size_t *next_fd);

/**
 * Cleanup the handle registry
 * 
 * WARNING: Should only be called when no other threads are using the registry.
 */
void brix_win32_cleanup_registry(void);

/* ==========================================================================
 * INLINE HELPERS (for performance-critical paths)
 * ========================================================================== */

/**
 * Quick inline conversion for file handles
 * Use brix_win32_fd_to_handle() for full validation
 */
static inline HANDLE
brix_win32_fd_to_handle_fast(int fd)
{
    /* Fast path - no validation, use only when fd is known valid */
    return (HANDLE)_get_osfhandle(fd);
}

/**
 * Check if fd is valid
 */
static inline int
brix_win32_is_valid_fd(int fd)
{
    return (fd >= 0 && _get_osfhandle(fd) != -1);
}

#endif /* BRIX_PLATFORM_WINDOWS */

#endif /* BRIX_WIN32_HANDLE_ABSTRACTION_H */
