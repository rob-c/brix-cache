/*
 * src/platform/platform.h - PAL host selection
 *
 * WHAT: Names the host directory the build selected and includes that host's
 *       own description (src/platform/<host>/host.h). This file contains no
 *       host conditional: the build passes -DBRIX_PLATFORM_HOST=<linux|darwin|
 *       windows> (repo-root ./config, client/Makefile, the host Makefiles) and
 *       every "which OS is this" decision lives under that directory.
 * WHY:  INVARIANT 14 — only the PAL knows which operating system it is on,
 *       and the PAL interface itself stays free of #if so it reads as one
 *       contract. tools/ci/check_platform_leak.py rejects OS macros anywhere
 *       outside src/platform/<host>/, client/lib/platform/<host>/ and
 *       shared/cvmfs/platform/.
 * HOW:  BRIX_PLAT_HOST_HEADER(name) stringifies "<host>/name" so each family
 *       header pulls its host counterpart with one computed #include:
 *         host.h         platform flags, capability gates (BRIX_HAS_*)
 *         host_endian.h  the native byte-order operations
 *         host_posix.h   the host's part of the POSIX surface
 *         host_api.h     host-only extensions (Apple Silicon, Win32)
 *       The host header defines BRIX_PLATFORM_LINUX / _DARWIN / _WINDOWS as
 *       0 or 1 for the host adapters' own bodies.
 */

#ifndef BRIX_PLATFORM_H
#define BRIX_PLATFORM_H

#ifndef BRIX_PLATFORM_HOST
#error "BRIX_PLATFORM_HOST is not defined: build with -DBRIX_PLATFORM_HOST=linux|darwin|windows (see ./config and client/Makefile)"
#endif

/* GCC and Clang predefine the bare token `linux` as 1 in GNU mode (the default
 * when no -std= is given). BRIX_PLATFORM_HOST expands before it is stringified
 * below, so on such a build "linux/host.h" became "1/host.h" and the computed
 * include failed. Retire every spelling a toolchain might predefine, so the
 * host name always reaches BRIX_PLAT_STR_ as a plain identifier. The client and
 * xrdproto Makefiles pass -std=c11, which hides these; the nginx module build
 * takes its flags from ./configure and does not. `#undef` of an undefined macro
 * is a no-op, so this is silent on hosts that predefine none of them. */
#undef linux
#undef darwin
#undef windows

#define BRIX_PLAT_STR_(x) #x
#define BRIX_PLAT_STR(x) BRIX_PLAT_STR_(x)
/* "<host>/name" for a computed #include; quoted, so it resolves next to the
 * including header (src/platform/ or client/lib/platform/). */
#define BRIX_PLAT_HOST_HEADER(name) BRIX_PLAT_STR(BRIX_PLATFORM_HOST/name)

#include BRIX_PLAT_HOST_HEADER(host.h)
#include "platform_arch.h"

/* Compiler attribute spellings (GCC and Clang on every supported host). */
#define BRIX_UNUSED     __attribute__((unused))
#define BRIX_NORETURN   __attribute__((noreturn))
#define BRIX_MALLOC     __attribute__((malloc))
#define BRIX_ALIGNED(x) __attribute__((aligned(x)))
/* BRIX_WEAK_REF (an optional symbol a binary may be linked without) is spelt
 * per host in <host>/host.h: ELF resolves an undefined weak function to
 * NULL; Mach-O needs weak_import. Test the reference against NULL. */

#endif /* BRIX_PLATFORM_H */
