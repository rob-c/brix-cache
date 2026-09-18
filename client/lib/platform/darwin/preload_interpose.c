/*
 * client/lib/platform/darwin/preload_interpose.c - the dyld interposing table
 *
 * WHAT: One __DATA,__interpose row per wrapped libc entry point, pairing the
 *       shim's brixposix_<name> with libSystem's <name>.
 * WHY:  dyld never lets an inserted library shadow libSystem by symbol name
 *       (two-level namespaces bind every call to the library it was linked
 *       against); this table is the supported way to redirect them, and it
 *       is applied to every image in the process except this one.
 * HOW:  BRIXPOSIX_WRAPPED (brixposix_internal.h) is the single list of what
 *       the shim interposes; a wrapper added there without a definition
 *       fails this object's link rather than silently doing nothing.
 */

#include "platform/preload.h"

#if BRIX_PLATFORM_DARWIN

#include "brixposix_internal.h"

#include <stdio.h>

typedef struct {
    const void *replacement;
    const void *original;
} brixposix_interpose_t;

/* libSystem exports fopen twice: the plain symbol, which programs built
 * against a strict POSIX level (or without <stdio.h>'s extension aliasing)
 * import, and fopen$DARWIN_EXTSN, which this file's own `fopen` reference
 * resolves to.  Both must be rows or half the callers keep libc's fopen. */
extern FILE *brixposix_libc_fopen_plain(const char *, const char *)
    __asm__("_fopen");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"   /* readdir_r */
#define BRIXPOSIX_INTERPOSE_ROW(name) \
    { (const void *) &BRIXPOSIX_WRAP(name), (const void *) &name },

__attribute__((used, section("__DATA,__interpose")))
static const brixposix_interpose_t brixposix_interposes[] = {
    BRIXPOSIX_WRAPPED(BRIXPOSIX_INTERPOSE_ROW)
    { (const void *) &BRIXPOSIX_WRAP(fopen),
      (const void *) &brixposix_libc_fopen_plain },
};
#pragma clang diagnostic pop

#endif /* BRIX_PLATFORM_DARWIN */
