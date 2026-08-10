#ifndef BRIXPOSIX_INTERNAL_H
#define BRIXPOSIX_INTERNAL_H
/*
 * brixposix_internal.h — state + helpers shared between the preload shim's
 * core (brixposix_preload.c) and the stat-family TU (brixposix_stat.c).
 *
 * NOT a public API. Every shared symbol carries visibility("hidden") so the
 * preloaded .so never exports it into the dynamic symbol table — the shim
 * must interpose libc's open/read/write/stat WITHOUT its own internal
 * helpers accidentally interposing (or being interposed by) the host
 * program's symbols. Only the intended libc wrappers keep default visibility.
 */
#include "brix.h"

#include <dlfcn.h>
#include <pthread.h>
#include <sys/stat.h>

#define BRIXPOSIX_HIDDEN __attribute__((visibility("hidden")))

/* Shadow file descriptors: fake numbers >= XFS_FD_BASE the shim hands out for
 * remote-backed opens (never real kernel fds). */
#define XFS_FD_BASE 0x40000000
#define XFS_FD_MAX  1024

typedef struct {
    int        used;
    int        write_mode; /* 1 = opened for writing (upload), 0 = read */
    brix_rfile f;          /* resilient: reopens + resumes after a sever */
    int64_t    pos;
    int64_t    size;
} xfs_slot;

/* Resolve (once) the real libc symbol behind the wrapper we're standing in.
 * The variable inherits libc's exact prototype via __typeof__(name). */
#define REAL(name)                                                      \
    static __typeof__(name) *real_##name = NULL;                        \
    if (real_##name == NULL) {                                          \
        real_##name = (__typeof__(name) *) dlsym(RTLD_NEXT, #name);     \
    }

BRIXPOSIX_HIDDEN extern pthread_mutex_t g_lock;
BRIXPOSIX_HIDDEN extern brix_conn       g_conn;

/* Lazily connect the single session (g_lock held by caller). 0 / -1. */
BRIXPOSIX_HIDDEN int       ensure_conn(void);
/* Resolve a shadow fd to its slot, or NULL for a real/unknown fd. */
BRIXPOSIX_HIDDEN xfs_slot *slot_of(int fd);
/* Map a local path under the BRIX_VMP prefix to the remote path; 0 = not ours. */
BRIXPOSIX_HIDDEN int       map_path(const char *path, char *out, size_t outsz);
/* One statinfo -> struct stat mapping (shared with the FUSE drivers). */
BRIXPOSIX_HIDDEN void      fill_stat(const brix_statinfo *si, struct stat *stbuf);

#endif /* BRIXPOSIX_INTERNAL_H */
