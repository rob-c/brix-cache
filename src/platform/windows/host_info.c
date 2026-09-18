/*
 * src/platform/windows/host_info.c - Windows host identity and sizing (stub-grade)
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "../platform_api.h"

const char *brix_plat_name(void) { return "windows"; }
int brix_plat_cpu_count(void) { return -1; }
uint64_t brix_plat_total_memory(void) { return 0; }
uint64_t brix_plat_available_memory(void) { return 0; }

#endif /* BRIX_PLATFORM_WINDOWS */
