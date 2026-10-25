/* Native FreeBSD host facts. Missing measurements stay explicitly unavailable. */
#include "../platform_api.h"
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>

/* WHAT: Return the configured host name. WHY: Diagnostics must identify the
 * actual adapter. HOW: Return immutable compile-selected text. */
const char *brix_plat_name(void) { return "freebsd"; }

/* WHAT: Return native online CPUs, at least one. WHY: Size bounded worker pools.
 * HOW: Use sysconf and preserve the conservative minimum on failure. */
int brix_plat_cpu_count(void)
{ long count = sysconf(_SC_NPROCESSORS_ONLN); return count > 0 ? (int) count : 1; }

/* WHAT: Return physical memory bytes or zero on unavailable measurement.
 * WHY: Do not substitute host process limits for physical RAM. HOW: Read sysctl. */
uint64_t brix_plat_total_memory(void)
{
    uint64_t bytes = 0;
    size_t length = sizeof(bytes);
    return sysctlbyname("hw.physmem", &bytes, &length, NULL, 0) == 0 ? bytes : 0;
}

/* WHAT: Read one native page counter, returning zero when unavailable.
 * WHY: Keep native integer widths out of portable memory accounting.
 * HOW: Query the exact unsigned-int sysctl type. */
static uint64_t freebsd_page_counter(const char *name)
{
    unsigned value = 0;
    size_t length = sizeof(value);
    return sysctlbyname(name, &value, &length, NULL, 0) == 0 ? value : 0;
}

/* WHAT: Return free plus inactive memory in bytes. WHY: Include reclaimable
 * pages without inventing a Linux MemAvailable value. HOW: Sum native counts. */
uint64_t brix_plat_available_memory(void)
{
    uint64_t pages = freebsd_page_counter("vm.stats.vm.v_free_count")
                     + freebsd_page_counter("vm.stats.vm.v_inactive_count");
    return pages * (uint64_t) sysconf(_SC_PAGESIZE);
}

/* WHAT: Check the user pointer's canonical low-half representation.
 * WHY: Reject corrupted indirect targets without dereferencing them.
 * HOW: Use the supported 64-bit user-address shape, matching the BSD contract. */
int brix_plat_pointer_is_canonical(const void *pointer)
{ return ((uintptr_t) pointer >> 48) == 0; }

/* WHAT: Return available load/memory observations. WHY: Missing network/page
 * counters must not masquerade as measured zeros. HOW: Set only measured bits. */
int brix_plat_sysload_sample(brix_plat_sysload_t *sample)
{
    if (sample == NULL) { errno = EINVAL; return -1; }
    memset(sample, 0, sizeof(*sample));
    if (getloadavg(&sample->load1, 1) == 1) { sample->have |= BRIX_SYSLOAD_HAVE_LOAD; }
    sample->total_memory = brix_plat_total_memory();
    sample->available_memory = brix_plat_available_memory();
    if (sample->total_memory != 0) { sample->have |= BRIX_SYSLOAD_HAVE_MEMORY; }
    return 0;
}
