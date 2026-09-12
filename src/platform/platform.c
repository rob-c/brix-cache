/*
 * src/platform/platform.c - Platform detection and initialization
 * 
 * This file provides platform information and PAL initialization.
 * All platform-specific logic lives here and in platform subdirectory wrappers.
 */

#include "platform.h"
#include "platform_api.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

#if BRIX_PLATFORM_DARWIN
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#endif

#if BRIX_PLATFORM_LINUX
#include <sys/sysinfo.h>
#endif

/* ==========================================================================
 * PLATFORM INFORMATION
 * ========================================================================== */

const char *
brix_plat_name(void)
{
#if BRIX_PLATFORM_LINUX
    return "linux";
#elif BRIX_PLATFORM_DARWIN
    return "darwin";
#else
    return "unknown";
#endif
}

const char *
brix_plat_version(void)
{
    static char version[256] = {0};
    
    if (version[0] != '\0') {
        return version;
    }
    
    struct utsname uts;
    if (uname(&uts) == 0) {
        strncpy(version, uts.release, sizeof(version) - 1);
        version[sizeof(version) - 1] = '\0';
    } else {
        strncpy(version, "unknown", sizeof(version) - 1);
    }
    
    return version;
}

const char *
brix_plat_arch(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__arm__) || defined(_M_ARM)
    return "arm";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "unknown";
#endif
}

int
brix_plat_is_root(void)
{
    return (getuid() == 0) ? 1 : 0;
}

int
brix_plat_cpu_count(void)
{
#if BRIX_PLATFORM_DARWIN
    int count = 0;
    size_t len = sizeof(count);
    
    if (sysctlbyname("hw.ncpu", &count, &len, NULL, 0) == 0) {
        return count;
    }
    return -1;
#elif BRIX_PLATFORM_LINUX
    return sysconf(_SC_NPROCESSORS_ONLN);
#else
    return -1;
#endif
}

uint64_t
brix_plat_total_memory(void)
{
#if BRIX_PLATFORM_DARWIN
    uint64_t mem = 0;
    size_t len = sizeof(mem);
    
    if (sysctlbyname("hw.memsize", &mem, &len, NULL, 0) == 0) {
        return mem;
    }
    return 0;
#elif BRIX_PLATFORM_LINUX
    struct sysinfo si;
    
    if (sysinfo(&si) == 0) {
        return (uint64_t)si.totalram * (uint64_t)si.mem_unit;
    }
    return 0;
#else
    return 0;
#endif
}

uint64_t
brix_plat_available_memory(void)
{
#if BRIX_PLATFORM_DARWIN
    vm_size_t page_size;
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    
    if (host_page_size(mach_host_self(), &page_size) == KERN_SUCCESS &&
        host_statistics64(mach_host_self(), HOST_VM_INFO64,
                         (host_info64_t)&vm_stat, &count) == KERN_SUCCESS)
    {
        uint64_t free_pages = vm_stat.free_count + 
                             vm_stat.inactive_count + 
                             vm_stat.purgeable_count;
        return free_pages * page_size;
    }
    return 0;
#elif BRIX_PLATFORM_LINUX
    struct sysinfo si;
    
    if (sysinfo(&si) == 0) {
        return (uint64_t)si.availram * (uint64_t)si.mem_unit;
    }
    return 0;
#else
    return 0;
#endif
}

/* ==========================================================================
 * INITIALIZATION
 * ========================================================================== */

int
brix_plat_init(void)
{
    return 0;
}

void
brix_plat_cleanup(void)
{
}
