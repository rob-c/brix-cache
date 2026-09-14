/* Windows alternate-stream enumeration; value operations remain in xattr.c. */
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
 * LIST EXTENDED ATTRIBUTES
 * ========================================================================== */

/*
 * Callback structure for enumerating ADS streams
 */
typedef struct {
    char *list;
    size_t size;
    size_t offset;
    int count;
} brix_win32_ads_enum_t;

/*
 * Enumerate all ADS streams on a file
 *
 * Uses FindFirstStreamW/FindNextStreamW to enumerate all alternate
 * data streams associated with the file.
 */
ssize_t
brix_plat_listxattr(const char *path, char *list, size_t size)
{
    wchar_t w_filepath[MAX_PATH];
    HANDLE find_handle;
    WIN32_FIND_STREAM_DATA stream_data;
    brix_win32_ads_enum_t enum_ctx;
    int result;

    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Convert path to wide string */
    result = MultiByteToWideChar(CP_UTF8, 0, path, -1, w_filepath, MAX_PATH);
    if (result == 0) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }

    /* Initialize enumeration context */
    enum_ctx.list = list;
    enum_ctx.size = size;
    enum_ctx.offset = 0;
    enum_ctx.count = 0;

    /* Find first stream */
    find_handle = FindFirstStreamW(w_filepath, FindStreamInfoStandard,
                                   &stream_data, 0);

    if (find_handle == INVALID_HANDLE_VALUE) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }

    do {
        /* Skip the default unnamed stream (::DATA) */
        if (wcscmp(stream_data.cStreamName, L"::DATA") == 0) {
            continue;
        }

        /* Convert stream name to UTF-8 */
        char stream_name[256];
        int name_len = WideCharToMultiByte(CP_UTF8, 0, stream_data.cStreamName, -1,
                                           stream_name, sizeof(stream_name),
                                           NULL, NULL);

        if (name_len == 0) {
            continue;  /* Skip invalid names */
        }

        name_len--;  /* Remove null terminator from length */

        /* If list buffer is NULL, just count */
        if (list == NULL || size == 0) {
            enum_ctx.offset += name_len + 1;  /* +1 for null separator */
            enum_ctx.count++;
            continue;
        }

        /* Check if buffer has space */
        if (enum_ctx.offset + name_len + 1 > size) {
            errno = ERANGE;
            FindClose(find_handle);
            return -1;
        }

        /* Copy stream name to list */
        memcpy(list + enum_ctx.offset, stream_name, name_len);
        list[enum_ctx.offset + name_len] = '\0';
        enum_ctx.offset += name_len + 1;
        enum_ctx.count++;

    } while (FindNextStreamW(find_handle, &stream_data));

    FindClose(find_handle);

    if (enum_ctx.count == 0) {
        errno = ENODATA;
        return -1;
    }

    return (ssize_t)enum_ctx.offset;
}

ssize_t
brix_plat_flistxattr(int fd, char *list, size_t size)
{
    /*
     * List extended attributes using file descriptor
     */
    char filepath[MAX_PATH];

    if (brix_win32_fd_path(fd, filepath, sizeof(filepath)) < 0) {
        return -1;
    }

    return brix_plat_listxattr((char *)filepath, list, size);
}

#endif /* BRIX_PLATFORM_WINDOWS */
