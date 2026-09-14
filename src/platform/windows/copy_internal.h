/* Buffered Windows transfer fallback. Requires: no prior headers. */
#pragma once
#include "../platform.h"
#if BRIX_PLATFORM_WINDOWS
#include <sys/types.h>
#include <stddef.h>
ssize_t brix_win32_buffered_copy(int in_fd, off_t *in_off, int out_fd,
                               off_t *out_off, size_t len);
#endif
