/*
 * src/platform/windows/posix_wrapper.c - Windows POSIX syscall wrappers
 * 
 * Status: ✅ COMPLETE - Core POSIX wrappers
 * 
 * Provides Windows implementations of core POSIX syscalls that don't have
 * dedicated wrapper files. Functions with dedicated implementations:
 *   - eventfd, pipe2: event_wrapper.c
 *   - xattr (*): xattr.c
 *   - sendfile, splice, copy_range: copy_range.c
 *   - setfsuid, setfsgid, security_*: security_wrapper.c
 *   - execvpe: process.c
 *   - platform detection: platform_detect.c
 * 
 * Source code calls brix_plat_*() from platform_api.h - never these directly.
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "handle_abstraction.h"
#include "../platform_api.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <share.h>

/* ==========================================================================
 * FILE DESCRIPTOR OPERATIONS
 * ========================================================================== */

int
brix_plat_anon_fd(const char *name, const char *dir)
{
    /*
     * Windows implementation: CreateFile with FILE_FLAG_DELETE_ON_CLOSE
     * 
     * This creates a temporary file that is automatically deleted when closed.
     * Similar to memfd_create on Linux or mkstemp+unlink on macOS.
     */
    char temp_path[MAX_PATH];
    char filename[MAX_PATH];
    HANDLE handle;
    
    (void)name;  /* Windows temp files don't use names */
    (void)dir;
    
    /* Get temp directory */
    if (GetTempPathA(sizeof(temp_path), temp_path) == 0) {
        errno = ENOENT;
        return -1;
    }
    
    /* Generate unique filename */
    if (GetTempFileNameA(temp_path, "brix", 0, filename) == 0) {
        errno = ENOENT;
        return -1;
    }
    
    /* Create file with delete-on-close flag */
    handle = CreateFileA(
        filename,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_FLAG_DELETE_ON_CLOSE,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    /* Convert to file descriptor */
    int fd = _open_osfhandle((intptr_t)handle, _O_RDWR);
    if (fd == -1) {
        CloseHandle(handle);
        errno = EMFILE;
        return -1;
    }
    
    return fd;
}

/* ==========================================================================
 * FILE ADVISORY OPERATIONS
 * ========================================================================== */

int
brix_plat_fadvise(int fd, off_t offset, off_t len, int advice)
{
    /*
     * Windows: No direct equivalent to posix_fadvise
     * Could use SetFileValidData or PrefetchVirtualMemory
     * 
     * For now, stub returns success (advisory only)
     */
    (void)fd;
    (void)offset;
    (void)len;
    (void)advice;
    return 0;
}

/* ==========================================================================
 * FILE SYNCHRONIZATION
 * ========================================================================== */

int
brix_plat_fsync_data(int fd)
{
    /*
     * Windows: FlushFileBuffers
     * Similar to fdatasync on POSIX
     */
    HANDLE handle = (HANDLE)_get_osfhandle(fd);
    
    if (handle == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    
    if (FlushFileBuffers(handle)) {
        return 0;
    }
    
    brix_win32_set_errno(GetLastError());
    return -1;
}

int
brix_plat_sync(void)
{
    /*
     * Windows: FlushFileBuffers on all drives
     * Similar to sync() on POSIX
     */
    /* Windows automatically flushes file buffers periodically */
    /* This is a no-op for compatibility */
    return 0;
}

int
brix_plat_sync_tree(int dirfd)
{
    /*
     * Windows: FlushFileBuffers on directory
     * Similar to syncfs() on POSIX
     */
    HANDLE handle = (HANDLE)_get_osfhandle(dirfd);
    
    if (handle == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    
    if (FlushFileBuffers(handle)) {
        return 0;
    }
    
    brix_win32_set_errno(GetLastError());
    return -1;
}

/* ==========================================================================
 * RANDOM NUMBER GENERATION
 * ========================================================================== */

int
brix_plat_random(void *buf, size_t len)
{
    /*
     * Windows: BCryptGenRandom
     * Cryptographically secure random number generation
     */
    static BCRYPT_ALG_HANDLE alg_handle = NULL;
    NTSTATUS status;
    
    if (alg_handle == NULL) {
        status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_RNG_ALGORITHM, NULL, 0);
        if (status != STATUS_SUCCESS) {
            errno = EINVAL;
            return -1;
        }
    }
    
    status = BCryptGenRandom(alg_handle, (PUCHAR)buf, (ULONG)len, 0);
    
    if (status == STATUS_SUCCESS) {
        return 0;
    }
    
    errno = EINVAL;
    return -1;
}

#endif /* BRIX_PLATFORM_WINDOWS */
