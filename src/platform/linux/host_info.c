/*
 * src/platform/linux/host_info.c - Linux host identity and sizing
 *
 * WHAT: brix_plat_name, brix_plat_cpu_count, brix_plat_total_memory and
 *       brix_plat_available_memory (platform_api_info.h) for Linux.
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_LINUX

#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int
brix_plat_pointer_is_canonical(const void *ptr)
{
    uintptr_t v = (uintptr_t) ptr;

#if BRIX_ARCH_ARM64
    /* Linux AArch64 exposes the full zero-extended 48-bit user VA range. */
    return (v >> 48) == 0;
#else
    /* x86-64 user mappings occupy the lower canonical 47-bit range. */
    return (v >> 47) == 0;
#endif
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

static void
sysload_net(brix_plat_sysload_t *sample)
{
    struct ifaddrs *all;
    struct ifaddrs *at;

    if (getifaddrs(&all) != 0) return;
    for (at = all; at != NULL; at = at->ifa_next) {
        struct rtnl_link_stats *stats;

        if (at->ifa_addr == NULL || at->ifa_data == NULL
            || at->ifa_addr->sa_family != AF_PACKET
            || (at->ifa_flags & IFF_LOOPBACK) != 0) continue;
        stats = at->ifa_data;
        sample->net_bytes += (uint64_t) stats->rx_bytes + stats->tx_bytes;
        sample->have |= BRIX_SYSLOAD_HAVE_NET;
    }
    freeifaddrs(all);
}

static void
sysload_paging(brix_plat_sysload_t *sample)
{
    char               key[64];
    unsigned long long value;
    FILE              *input = fopen("/proc/vmstat", "r");

    if (input == NULL) return;
    while (fscanf(input, "%63s %llu", key, &value) == 2) {
        if (strcmp(key, "pgmajfault") == 0) {
            sample->paging_events = (uint64_t) value;
            sample->have |= BRIX_SYSLOAD_HAVE_PAGING;
            break;
        }
    }
    fclose(input);
}

int
brix_plat_sysload_sample(brix_plat_sysload_t *sample)
{
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
    sysload_net(sample);
    sysload_paging(sample);
    return sample->have != 0 ? 0 : -1;
}

#endif /* BRIX_PLATFORM_LINUX */
