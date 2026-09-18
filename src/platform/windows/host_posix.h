/*
 * src/platform/windows/host_posix.h - the Windows part of the PAL POSIX surface
 *
 * WHAT: ssize_t and the openat2(2) ABI for the stub adapters.
 */

#ifndef BRIX_PLATFORM_WINDOWS_HOST_POSIX_H
#define BRIX_PLATFORM_WINDOWS_HOST_POSIX_H

#include <BaseTsd.h>
#if !defined(_SSIZE_T_DEFINED) && !defined(BRIX_PLAT_SSIZE_T_DEFINED)
#define BRIX_PLAT_SSIZE_T_DEFINED 1
typedef SSIZE_T ssize_t;
#endif
#include "../openat2_abi.h"

#endif /* BRIX_PLATFORM_WINDOWS_HOST_POSIX_H */
