/*
 * src/platform/openat2_abi.h - the openat2(2) ABI for hosts without <linux/openat2.h>
 *
 * WHAT: RESOLVE_* values and struct open_how exactly as the Linux kernel
 *       defines them, so brix_plat_openat2 callers use one spelling on every
 *       host (Darwin emulates the semantics; a pre-5.6 Linux toolchain lacks
 *       the header). Included only by the host_posix.h files that need it.
 */

#ifndef BRIX_PLATFORM_OPENAT2_ABI_H
#define BRIX_PLATFORM_OPENAT2_ABI_H

#include <stdint.h>

#define RESOLVE_NO_XDEV       0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS   0x04
#define RESOLVE_BENEATH       0x08
#define RESOLVE_IN_ROOT       0x10
#define RESOLVE_CACHED        0x20

struct open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

#endif /* BRIX_PLATFORM_OPENAT2_ABI_H */
