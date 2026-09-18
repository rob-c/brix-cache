/*
 * client/lib/platform/linux/preload.h - LD_PRELOAD interposition
 *
 * A wrapper carries libc's own name: the preloaded object precedes libc in
 * the global symbol search, so every image's call lands on it. The real
 * function is the next definition after ours (RTLD_NEXT).
 */
#ifndef BRIX_CLIENT_PLATFORM_LINUX_PRELOAD_H
#define BRIX_CLIENT_PLATFORM_LINUX_PRELOAD_H

#include <dlfcn.h>

#define BRIXPOSIX_WRAP(name)         name
#define BRIXPOSIX_REAL_RESOLVE(name) ((__typeof__(name) *) dlsym(RTLD_NEXT, #name))

/* glibc's dirent carries the seek cursor as d_off; the name length is implied. */
#define BRIXPOSIX_DIRENT_FINISH(de, cursor, namelen) \
    do { (de)->d_off = (off_t) (cursor); (void) (namelen); } while (0)

#endif /* BRIX_CLIENT_PLATFORM_LINUX_PRELOAD_H */
