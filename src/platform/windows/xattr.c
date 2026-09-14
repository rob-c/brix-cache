/*
 * src/platform/windows/xattr.c - Windows Extended Attributes via NTFS ADS
 * 
 * Status: 🚧 DRAFT - Implementation for Windows PAL
 * 
 * This file implements POSIX-style extended attributes using NTFS Alternate
 * Data Streams (ADS). ADS allows multiple data streams associated with a
 * single file, which maps well to the xattr concept.
 * 
 * Implementation Approach:
 * - Attribute names mapped to ADS stream names: "user.attr" → ":user.attr"
 * - Uses CreateFileW with ":stream_name" syntax
 * - All streams are unnamed (default) or named streams
 * - NTFS-only: FAT32/exFAT do not support ADS
 * 
 * Limitations:
 * - NTFS filesystem required (FAT32/exFAT/ReFS not supported)
 * - Stream names have limitations (no :, \, /, *, ?, ", <, >, |)
 * - Maximum stream name length: 255 characters
 * - Security descriptors may differ from POSIX xattr permissions
 * - Some antivirus software may flag ADS usage
 * 
 * References:
 * - https://docs.microsoft.com/en-us/windows/win32/fileio/alternate-data-streams
 * - https://blogs.msdn.microsoft.com/oldnewthing/20151229-00/?p=92111
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "path_internal.h"
#include "xattr_internal.h"
#include "../platform_api.h"

#include <windows.h>
#include <io.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ==========================================================================
 * ADS NAME MAPPING
 * ========================================================================== */

/*
 * Convert POSIX xattr name to NTFS ADS name
 * 
 * POSIX: "user.myattr"
 * NTFS:  "filepath:user.myattr"
 * 
 * The ADS name is appended to the file path with a colon separator.
 * We use the "user." namespace prefix as-is for compatibility.
 */
static int
brix_win32_ads_build_path(const char *filepath, const char *attr_name,
                          wchar_t *ads_path, size_t ads_path_size)
{
    wchar_t w_filepath[MAX_PATH];
    wchar_t w_attr_name[256];
    int result;
    
    /* Convert filepath to wide string */
    result = MultiByteToWideChar(CP_UTF8, 0, filepath, -1, w_filepath, MAX_PATH);
    if (result == 0) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    /* Convert attribute name to wide string */
    result = MultiByteToWideChar(CP_UTF8, 0, attr_name, -1, w_attr_name, 256);
    if (result == 0) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    /* Build ADS path: "filepath:attr_name" */
    if (wcslen(w_filepath) + wcslen(w_attr_name) + 2 >= ads_path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    
    wcscpy(ads_path, w_filepath);
    wcscat(ads_path, L":");
    wcscat(ads_path, w_attr_name);
    
    return 0;
}

/*
 * Validate ADS stream name
 * 
 * ADS names cannot contain: : \ / * ? " < > |
 * And must not be empty or too long
 */
static int
brix_win32_ads_validate_name(const char *name)
{
    const char *invalid_chars = ":\\/*?\"<>|";
    const char *p;
    size_t len;
    
    if (name == NULL || name[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    
    len = strlen(name);
    if (len > 255) {
        errno = ENAMETOOLONG;
        return -1;
    }
    
    /* Check for invalid characters */
    for (p = name; *p != '\0'; p++) {
        if (strchr(invalid_chars, *p) != NULL) {
            errno = EINVAL;
            return -1;
        }
    }
    
    return 0;
}

/* ==========================================================================
 * EXTENDED ATTRIBUTE OPERATIONS
 * ========================================================================== */

ssize_t
brix_plat_getxattr(const char *path, const char *name, void *value, size_t size)
{
    /*
     * Get extended attribute using NTFS ADS
     * 
     * Opens the alternate data stream and reads its contents.
     * Returns the size of the attribute data, or -1 on error.
     * 
     * If value is NULL or size is 0, returns the required size.
     * 
     * Note: BRIX_XATTR_NOFOLLOW flag is NOT IMPLEMENTED on Windows.
     * This function always follows symlinks. If symlink protection is
     * required, check for FILE_ATTRIBUTE_REPARSE_POINT manually before
     * calling this function.
     */
    /* Note: flags parameter not present in getxattr, NOFOLLOW check N/A */
    wchar_t ads_path[MAX_PATH + 256];
    HANDLE handle;
    DWORD bytes_read;
    LARGE_INTEGER file_size;
    
    if (brix_win32_ads_validate_name(name) < 0) {
        return -1;
    }
    
    if (brix_win32_ads_build_path(path, name, ads_path, sizeof(ads_path)/sizeof(wchar_t)) < 0) {
        return -1;
    }
    
    /* Open the ADS */
    handle = CreateFileW(
        ads_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_HANDLE_EOF) {
            /* Stream doesn't exist - map to ENODATA */
            errno = ENODATA;
        } else {
            brix_win32_set_errno(error);
        }
        return -1;
    }
    
    /* Get stream size */
    if (!GetFileSizeEx(handle, &file_size)) {
        brix_win32_set_errno(GetLastError());
        CloseHandle(handle);
        return -1;
    }
    
    /* If value buffer is NULL, return required size */
    if (value == NULL || size == 0) {
        CloseHandle(handle);
        return (ssize_t)file_size.QuadPart;
    }
    
    /* Read the stream contents */
    if (file_size.QuadPart > (LONGLONG)size) {
        /* Buffer too small */
        CloseHandle(handle);
        errno = ERANGE;
        return -1;
    }
    
    if (!ReadFile(handle, value, (DWORD)file_size.QuadPart, &bytes_read, NULL)) {
        brix_win32_set_errno(GetLastError());
        CloseHandle(handle);
        return -1;
    }
    
    CloseHandle(handle);
    return (ssize_t)bytes_read;
}

/* ---- Validate an ADS name and resolve its descriptor path ----
 * WHAT: Return zero for a valid name/path combination, otherwise -1.
 * WHY: All three fd-based value operations share this validation contract.
 * HOW: 1. Validate the attribute name. 2. Resolve the fd's native path.
 *      3. Validate that the combined alternate-stream path fits.
 */
static int
brix_win32_xattr_fd_path(int fd, const char *name, char *path, size_t size)
{
    wchar_t ads_path[MAX_PATH + 256];
    if (brix_win32_ads_validate_name(name) < 0) {
        return -1;
    }
    if (brix_win32_fd_path(fd, path, size) < 0) {
        return -1;
    }
    return brix_win32_ads_build_path(path, name, ads_path,
                                    sizeof(ads_path) / sizeof(wchar_t));
}

ssize_t
brix_plat_fgetxattr(int fd, const char *name, void *value, size_t size)
{
    /*
     * Get extended attribute using file descriptor
     * 
     * Converts fd to HANDLE, then uses GetFinalPathNameByHandleW
     * to get the filepath, then proceeds as getxattr.
     */
    char filepath[MAX_PATH];
    if (brix_win32_xattr_fd_path(fd, name, filepath, sizeof(filepath)) < 0) {
        return -1;
    }
    return brix_plat_getxattr((char *)filepath, name, value, size);
}

int
brix_plat_setxattr(const char *path, const char *name,
                   const void *value, size_t size, int flags)
{
    /*
     * Set extended attribute using NTFS ADS
     * 
     * Creates or opens the alternate data stream and writes the value.
     * 
     * Flags:
     * - 0 or BRIX_XATTR_CREATE: Create new stream (fail if exists)
     * - BRIX_XATTR_REPLACE: Replace existing stream (fail if not exists)
     * - BRIX_XATTR_NOFOLLOW: ⚠️ NOT IMPLEMENTED on Windows (returns EINVAL)
     * 
     * BRIX_XATTR_NOFOLLOW Limitation:
     * - Windows NTFS ADS operations always follow symlinks by default
     * - Would require FILE_FLAG_OPEN_REPARSE_POINT + complex path handling
     * - If this flag is set, we return EINVAL to indicate unsupported operation
     * - Security implication: Attributes may be set on symlink target, not link
     * - Workaround: Check for symlinks manually with GetFileAttributesW()
     *   before calling setxattr if symlink protection is required
     * 
     * References:
     * - https://docs.microsoft.com/en-us/windows/win32/fileio/reparse-points
     * - https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
     */
    
    /* Check for unsupported BRIX_XATTR_NOFOLLOW flag */
    if (flags & BRIX_XATTR_NOFOLLOW) {
        errno = EINVAL;  /* Flag not supported on Windows */
        return -1;
    }
    wchar_t ads_path[MAX_PATH + 256];
    HANDLE handle;
    DWORD bytes_written;
    DWORD disposition;
    
    if (brix_win32_ads_validate_name(name) < 0) {
        return -1;
    }
    
    if (brix_win32_ads_build_path(path, name, ads_path, sizeof(ads_path)/sizeof(wchar_t)) < 0) {
        return -1;
    }
    
    /* Determine creation disposition based on flags */
    if (flags & BRIX_XATTR_CREATE) {
        /* Create new, fail if exists */
        disposition = CREATE_NEW;
    } else if (flags & BRIX_XATTR_REPLACE) {
        /* Open existing, fail if not exists */
        disposition = OPEN_EXISTING;
    } else {
        /* Create or overwrite */
        disposition = CREATE_ALWAYS;
    }
    
    /* Create/open the ADS */
    handle = CreateFileW(
        ads_path,
        GENERIC_WRITE,
        0,  /* No sharing */
        NULL,
        disposition,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_EXISTS && (flags & BRIX_XATTR_CREATE)) {
            errno = EEXIST;
        } else if (error == ERROR_FILE_NOT_FOUND && (flags & BRIX_XATTR_REPLACE)) {
            errno = ENODATA;
        } else {
            brix_win32_set_errno(error);
        }
        return -1;
    }
    
    /* Write the value */
    if (size > 0 && value != NULL) {
        if (!WriteFile(handle, value, (DWORD)size, &bytes_written, NULL)) {
            brix_win32_set_errno(GetLastError());
            CloseHandle(handle);
            return -1;
        }
        
        if (bytes_written != (DWORD)size) {
            errno = EIO;
            CloseHandle(handle);
            return -1;
        }
    }
    
    CloseHandle(handle);
    return 0;
}

int
brix_plat_fsetxattr(int fd, const char *name,
                    const void *value, size_t size, int flags)
{
    /*
     * Set extended attribute using file descriptor
     * 
     * Similar to fgetxattr, converts fd to path first.
     * 
     * Note: BRIX_XATTR_NOFOLLOW flag is NOT IMPLEMENTED on Windows.
     * Returns EINVAL if this flag is set.
     */
    
    /* Check for unsupported BRIX_XATTR_NOFOLLOW flag */
    if (flags & BRIX_XATTR_NOFOLLOW) {
        errno = EINVAL;  /* Flag not supported on Windows */
        return -1;
    }
    char filepath[MAX_PATH];
    if (brix_win32_xattr_fd_path(fd, name, filepath, sizeof(filepath)) < 0) {
        return -1;
    }
    return brix_plat_setxattr((char *)filepath, name, value, size, flags);
}

int
brix_plat_removexattr(const char *path, const char *name)
{
    /*
     * Remove extended attribute using NTFS ADS
     * 
     * Deletes the alternate data stream using DeleteFileW.
     */
    wchar_t ads_path[MAX_PATH + 256];
    
    if (brix_win32_ads_validate_name(name) < 0) {
        return -1;
    }
    
    if (brix_win32_ads_build_path(path, name, ads_path, sizeof(ads_path)/sizeof(wchar_t)) < 0) {
        return -1;
    }
    
    /* Delete the ADS */
    if (!DeleteFileW(ads_path)) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            errno = ENODATA;
        } else {
            brix_win32_set_errno(error);
        }
        return -1;
    }
    
    return 0;
}

int
brix_plat_fremovexattr(int fd, const char *name)
{
    /*
     * Remove extended attribute using file descriptor
     */
    char filepath[MAX_PATH];
    if (brix_win32_xattr_fd_path(fd, name, filepath, sizeof(filepath)) < 0) {
        return -1;
    }
    return brix_plat_removexattr((char *)filepath, name);
}

/* ==========================================================================
 * ADS UTILITY FUNCTIONS
 * ========================================================================== */

/*
 * Check if a path is on an NTFS volume
 * 
 * Returns 1 if NTFS, 0 if not NTFS or error
 */
int
brix_win32_is_ntfs_path(const char *path)
{
    wchar_t w_filepath[MAX_PATH];
    wchar_t volume_path[MAX_PATH];
    wchar_t fs_name[64];
    int result;
    
    if (path == NULL) {
        return 0;
    }
    
    /* Convert to wide string */
    result = MultiByteToWideChar(CP_UTF8, 0, path, -1, w_filepath, MAX_PATH);
    if (result == 0) {
        return 0;
    }
    
    /* Get volume path */
    if (!GetVolumePathNameW(w_filepath, volume_path, MAX_PATH)) {
        return 0;
    }
    
    /* Get volume information */
    if (!GetVolumeInformationW(volume_path, NULL, 0, NULL, NULL, NULL,
                               fs_name, sizeof(fs_name)/sizeof(wchar_t))) {
        return 0;
    }
    
    /* Check if filesystem is NTFS */
    return (wcscmp(fs_name, L"NTFS") == 0) ? 1 : 0;
}

/*
 * Get ADS size without reading contents
 */
ssize_t
brix_win32_ads_get_size(const char *path, const char *name)
{
    wchar_t ads_path[MAX_PATH + 256];
    HANDLE handle;
    LARGE_INTEGER file_size;
    
    if (brix_win32_ads_build_path(path, name, ads_path, sizeof(ads_path)/sizeof(wchar_t)) < 0) {
        return -1;
    }
    
    handle = CreateFileW(
        ads_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    if (!GetFileSizeEx(handle, &file_size)) {
        brix_win32_set_errno(GetLastError());
        CloseHandle(handle);
        return -1;
    }
    
    CloseHandle(handle);
    return (ssize_t)file_size.QuadPart;
}

#endif /* BRIX_PLATFORM_WINDOWS */
