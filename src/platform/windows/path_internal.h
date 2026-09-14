/* Handle-to-path conversion shared by Windows transfer and xattr owners.
 * Requires: no prior headers; native HANDLE and size_t are included.
 */
#pragma once
#include "../platform.h"
#if BRIX_PLATFORM_WINDOWS
#include <winsock2.h>
#include <windows.h>
#include <stddef.h>
int brix_win32_get_file_path(HANDLE handle, char *path, size_t path_size);
int brix_win32_fd_path(int fd, char *path, size_t path_size);
#endif
