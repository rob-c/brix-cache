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
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <stdlib.h>
#include <string.h>
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

int
brix_plat_pointer_is_canonical(const void *ptr)
{
    return ((uintptr_t) ptr >> 47) == 0;
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

static void
sysload_net(brix_plat_sysload_t *sample)
{
    int     mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0 };
    size_t  len = 0;
    char   *table;
    char   *at;
    char   *end;

    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &len, NULL, 0) != 0
        || len == 0) return;
    table = malloc(len);
    if (table == NULL) return;
    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), table, &len, NULL, 0) != 0) {
        free(table);
        return;
    }
    end = table + len;
    for (at = table; at + sizeof(struct if_msghdr) <= end; ) {
        struct if_msghdr *base = (struct if_msghdr *) at;

        if (base->ifm_msglen == 0 || at + base->ifm_msglen > end) break;
        if (base->ifm_type == RTM_IFINFO2
            && base->ifm_msglen >= sizeof(struct if_msghdr2)) {
            struct if_msghdr2 *info = (struct if_msghdr2 *) at;

            if ((info->ifm_flags & IFF_LOOPBACK) == 0
                && info->ifm_data.ifi_type != IFT_LOOP) {
                sample->net_bytes += info->ifm_data.ifi_ibytes
                    + info->ifm_data.ifi_obytes;
                sample->have |= BRIX_SYSLOAD_HAVE_NET;
            }
        }
        at += base->ifm_msglen;
    }
    free(table);
}

int
brix_plat_sysload_sample(brix_plat_sysload_t *sample)
{
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;

    if (sample == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(sample, 0, sizeof(*sample));
    if (getloadavg(&sample->load1, 1) == 1) {
        sample->have |= BRIX_SYSLOAD_HAVE_LOAD;
    }
    sample->total_memory = brix_plat_total_memory();
    sample->available_memory = brix_plat_available_memory();
    if (sample->total_memory != 0) sample->have |= BRIX_SYSLOAD_HAVE_MEMORY;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
            (host_info64_t) &vm_stat, &count) == KERN_SUCCESS) {
        sample->paging_events = (uint64_t) vm_stat.pageins
            + (uint64_t) vm_stat.pageouts;
        sample->have |= BRIX_SYSLOAD_HAVE_PAGING;
    }
    sysload_net(sample);
    return sample->have != 0 ? 0 : -1;
}

#endif /* BRIX_PLATFORM_DARWIN */
