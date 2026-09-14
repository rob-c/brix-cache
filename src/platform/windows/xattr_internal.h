/* Windows alternate-stream utility declarations. Requires: no prior headers. */
#pragma once
#include "../platform.h"
#if BRIX_PLATFORM_WINDOWS
int brix_win32_is_ntfs_path(const char *path);
#endif
