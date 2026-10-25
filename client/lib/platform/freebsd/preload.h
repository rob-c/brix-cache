/* FreeBSD ELF interposition: resolve libc after this image, never recurse. */
#pragma once
#include <dlfcn.h>
/* epoll-shim redirects client socket cleanup through a close macro. The
 * interposition frontend must export libc's actual name, not accidentally
 * replace epoll_shim_close while leaving close unresolved. Other client TUs
 * keep their host macro and the dependency's own descriptor bookkeeping. */
#undef close
#define BRIXPOSIX_WRAP(name) name
#define BRIXPOSIX_REAL_RESOLVE(name) ((__typeof__(name) *) dlsym(RTLD_NEXT, #name))
#define BRIXPOSIX_DIRENT_FINISH(entry, cursor, length) \
    do { (entry)->d_off = (off_t) (cursor); (entry)->d_namlen = (length); } while (0)
