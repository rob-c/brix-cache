/* Darwin integer sysctl queries with caller-selected failure values.
 * Requires: the native sysctlbyname declaration; no nginx dependency.
 */
#pragma once

#include <stddef.h>
#include <sys/sysctl.h>

static inline int
brix_darwin_sysctl_read_int(const char *name, int *value)
{
    size_t size = sizeof(*value);

    return sysctlbyname(name, value, &size, NULL, 0);
}

static inline int
brix_darwin_sysctl_int(const char *name, int fallback)
{
    int value = 0;

    return brix_darwin_sysctl_read_int(name, &value) == 0 ? value : fallback;
}
