/*
 * src/platform/platform_runtime.c (host-free: name, CPU and memory sizing live in <host>/host_info.c) - Platform detection and initialization
 * 
 * Host-free PAL runtime: kernel release, architecture, root check, init.
 * Everything that differs per host lives under src/platform/<host>/.
 */

#include "platform.h"
#include "platform_api.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

/* ==========================================================================
 * HOST-FREE RUNTIME INFORMATION
 * (brix_plat_name, CPU and memory sizing are per host: <host>/host_info.c)
 * ========================================================================== */

const char *
brix_plat_version(void)
{
    static char    version[256] = {0};
    struct utsname uts;

    if (version[0] != '\0') {
        return version;
    }
    if (uname(&uts) == 0) {
        strncpy(version, uts.release, sizeof(version) - 1);
    } else {
        strncpy(version, "unknown", sizeof(version) - 1);
    }
    version[sizeof(version) - 1] = '\0';
    return version;
}

const char *
brix_plat_arch(void)
{
#if BRIX_ARCH_X86_64
    return "x86_64";
#elif BRIX_ARCH_ARM64
    return "arm64";
#else
    return "unknown";
#endif
}

int
brix_plat_is_root(void)
{
    return (getuid() == 0) ? 1 : 0;
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
