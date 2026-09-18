/*
 * src/platform/linux/host_posix.h - the Linux part of the PAL POSIX surface
 *
 * WHAT: The glibc/kernel headers the portable tree may not name itself, and
 *       the openat2(2) ABI (from <linux/openat2.h> when the toolchain has it).
 */

#ifndef BRIX_PLATFORM_LINUX_HOST_POSIX_H
#define BRIX_PLATFORM_LINUX_HOST_POSIX_H

#include <endian.h>
#include <sys/xattr.h>
#include <sys/eventfd.h>
#include <sys/sysmacros.h>
#include <sys/random.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>

#if defined(__has_include)
#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#define BRIX_PLAT_HAVE_OPENAT2_H 1
#endif
#endif
#if !defined(BRIX_PLAT_HAVE_OPENAT2_H)
#include "../openat2_abi.h"
#endif

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

#endif /* BRIX_PLATFORM_LINUX_HOST_POSIX_H */
