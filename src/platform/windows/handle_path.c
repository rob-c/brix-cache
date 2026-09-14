/* Windows handle path resolution shared by transfer and ADS operations.
 * The canonical conversion was previously private to copy_range.c.
 */
#include "path_internal.h"
#if BRIX_PLATFORM_WINDOWS
#include "win32_compat.h"
#include <string.h>
#include <errno.h>
#include <io.h>
/**
 * brix_win32_get_file_path - Get file path from handle
 *
 * @handle: File handle
 * @path: Output buffer for path
 * @path_size: Size of output buffer
 * @return: 0 on success, -1 on error
 */
int
brix_win32_get_file_path(HANDLE handle, char *path, size_t path_size)
{
    DWORD path_len;

    path_len = GetFinalPathNameByHandleA(handle, path, (DWORD)path_size, 0);
    if (path_len == 0) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    if (path_len >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Remove \\?\ prefix if present */
    if (strncmp(path, "\\\\?\\", 4) == 0) {
        memmove(path, path + 4, strlen(path) - 3);
    }

    return 0;
}

/* ---- Resolve the native path of an open CRT descriptor ----
 * WHAT: Return zero with the path, or -1 for an invalid fd/path lookup.
 * WHY: ADS fd operations must share one conversion and bounded char buffer.
 * HOW: 1. Resolve the fd's handle. 2. Delegate to the existing path owner.
 */
int
brix_win32_fd_path(int fd, char *path, size_t path_size)
{
    HANDLE handle = (HANDLE)_get_osfhandle(fd);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    return brix_win32_get_file_path(handle, path, path_size);
}
#endif /* BRIX_PLATFORM_WINDOWS */
