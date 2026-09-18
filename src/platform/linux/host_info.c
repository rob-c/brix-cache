/*
 * src/platform/linux/host_info.c - Linux host identity and sizing
 *
 * WHAT: brix_plat_name, brix_plat_cpu_count, brix_plat_total_memory and
 *       brix_plat_available_memory (platform_api_info.h) for Linux.
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_LINUX

#include <sys/sysinfo.h>
#include <unistd.h>

const char *
brix_plat_name(void)
{
    return "linux";
}

int
brix_plat_cpu_count(void)
{
    return (int) sysconf(_SC_NPROCESSORS_ONLN);
}

uint64_t
brix_plat_total_memory(void)
{
    struct sysinfo si;

    if (sysinfo(&si) == 0) {
        return (uint64_t) si.totalram * (uint64_t) si.mem_unit;
    }
    return 0;
}

uint64_t
brix_plat_available_memory(void)
{
    struct sysinfo si;

    if (sysinfo(&si) == 0) {
        return (uint64_t) si.freeram * (uint64_t) si.mem_unit;
    }
    return 0;
}

#endif /* BRIX_PLATFORM_LINUX */
