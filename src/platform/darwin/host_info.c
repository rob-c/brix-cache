/*
 * src/platform/darwin/host_info.c - macOS host identity and sizing
 *
 * WHAT: brix_plat_name, brix_plat_cpu_count, brix_plat_total_memory and
 *       brix_plat_available_memory (platform_api_info.h) for Darwin.
 * HOW:  sysctl for the static figures, Mach host statistics for free memory
 *       (free + inactive + purgeable pages).
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_DARWIN

#include "sysctl_value.h"
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>

const char *
brix_plat_name(void)
{
    return "darwin";
}

int
brix_plat_cpu_count(void)
{
    return brix_darwin_sysctl_int("hw.ncpu", -1);
}

uint64_t
brix_plat_total_memory(void)
{
    uint64_t mem = 0;
    size_t   len = sizeof(mem);

    if (sysctlbyname("hw.memsize", &mem, &len, NULL, 0) == 0) {
        return mem;
    }
    return 0;
}

uint64_t
brix_plat_available_memory(void)
{
    vm_size_t              page_size;
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;

    if (host_page_size(mach_host_self(), &page_size) == KERN_SUCCESS
        && host_statistics64(mach_host_self(), HOST_VM_INFO64,
                             (host_info64_t) &vm_stat, &count) == KERN_SUCCESS)
    {
        uint64_t free_pages = vm_stat.free_count + vm_stat.inactive_count
                              + vm_stat.purgeable_count;
        return free_pages * page_size;
    }
    return 0;
}

#endif /* BRIX_PLATFORM_DARWIN */
