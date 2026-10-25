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

/* WHAT: Reach libSystem's original stat from inside the interposing image.
 * WHY: dyld excludes this image's own references from its interpose table.
 * HOW: Call the ABI-correct libc spelling directly. */
int
brix_plat_preload_stat(const char *path, struct stat *out)
{
    return stat(path, out);
}

/* WHAT: Preserve real local symlink metadata on Darwin.
 * WHY: Non-prefix paths must never acquire remote metadata semantics.
 * HOW: Call libSystem's lstat from the interposing image itself. */
int
brix_plat_preload_lstat(const char *path, struct stat *out)
{
    return lstat(path, out);
}

/* WHAT: Describe a real Darwin kernel descriptor.
 * WHY: Only the common body handles the shim's shadow descriptors.
 * HOW: Invoke libSystem's original fstat directly. */
int
brix_plat_preload_fstat(int fd, struct stat *out)
{
    return fstat(fd, out);
}

/* WHAT: Preserve real directory-relative stat semantics on Darwin.
 * WHY: Host-specific ABI resolution belongs to the preload PAL.
 * HOW: Call libSystem's fstatat with unchanged arguments. */
int
brix_plat_preload_fstatat(int dirfd, const char *path, struct stat *out, int flags)
{
    return fstatat(dirfd, path, out, flags);
}

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
