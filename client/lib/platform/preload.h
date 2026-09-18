/*
 * client/lib/platform/preload.h - how the POSIX shim stands in for libc
 *
 * WHAT: The umbrella the preload shim (client/preload/) includes for the two
 *       things that differ per dynamic linker: what a wrapper is CALLED and
 *       how the real libc function behind it is REACHED. No host conditional
 *       lives here; <host>/preload.h supplies both through the same computed
 *       include the rest of the PAL uses.
 * WHY:  glibc's LD_PRELOAD and dyld's DYLD_INSERT_LIBRARIES interpose in
 *       opposite ways. Under LD_PRELOAD the shim defines `open` itself and
 *       the next definition down the search order is libc's. Under dyld a
 *       library that defined `open` would replace nothing: interposition is
 *       an explicit __interpose table pairing a differently named wrapper
 *       with the libSystem symbol, and the shim's own references stay bound
 *       to libSystem.
 * HOW:  BRIXPOSIX_WRAP(name)         the wrapper's identifier
 *       BRIXPOSIX_REAL_RESOLVE(name) an expression yielding libc's function
 */
#ifndef BRIX_CLIENT_PLATFORM_PRELOAD_H
#define BRIX_CLIENT_PLATFORM_PRELOAD_H

#include "platform/platform.h"
#include BRIX_PLAT_HOST_HEADER(preload.h)

#endif /* BRIX_CLIENT_PLATFORM_PRELOAD_H */
