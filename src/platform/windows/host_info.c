/*
 * src/platform/windows/host_info.c - Windows host identity and sizing (stub-grade)
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "../platform_api.h"
#include <errno.h>
#include <string.h>

const char *brix_plat_name(void) { return "windows"; }
int brix_plat_cpu_count(void) { return -1; }
int brix_plat_pointer_is_canonical(const void *ptr)
{
    uintptr_t v = (uintptr_t) ptr;

#if BRIX_ARCH_ARM64
    return (v >> 48) == 0;
#else
    return (v >> 47) == 0;
#endif
}
uint64_t brix_plat_total_memory(void) { return 0; }
uint64_t brix_plat_available_memory(void) { return 0; }
int brix_plat_sysload_sample(brix_plat_sysload_t *sample)
{
    if (sample == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(sample, 0, sizeof(*sample));
    errno = ENOSYS;
    return -1;
}

#endif /* BRIX_PLATFORM_WINDOWS */
