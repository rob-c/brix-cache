#ifndef BRIXPOSIX_INTERNAL_H
#define BRIXPOSIX_INTERNAL_H
/*
 * brixposix_internal.h — state + helpers shared between the preload shim's
 * TUs (brixposix_preload/stat/dir/stdio.c) and its host halves under
 * client/lib/platform/<host>/preload_*.c.
 *
 * NOT a public API. Every shared symbol carries visibility("hidden") so the
 * preloaded .so never exports it into the dynamic symbol table — the shim
 * must interpose libc's open/read/write/stat WITHOUT its own internal
 * helpers accidentally interposing (or being interposed by) the host
 * program's symbols. Only the intended libc wrappers keep default visibility.
 */
#include "brix.h"
#include "platform/preload.h"   /* BRIXPOSIX_WRAP / BRIXPOSIX_REAL_RESOLVE per host */

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define BRIXPOSIX_HIDDEN __attribute__((visibility("hidden")))

/*
 * The ONE list of libc entry points the shim interposes.  A wrapper is
 * defined as BRIXPOSIX_WRAP(name) — libc's own name under LD_PRELOAD,
 * brixposix_<name> under dyld, where darwin/preload_interpose.c turns this
 * list into the __interpose table.  The glibc-only *64 names and statx are
 * not here: linux/preload_lfs.c forwards them to these.
 */
#define BRIXPOSIX_WRAPPED(X) \
    X(open) X(openat) X(read) X(pread) X(write) X(pwrite) X(lseek) X(close) \
    X(stat) X(lstat) X(fstat) X(fstatat) X(access) \
    X(opendir) X(readdir) X(readdir_r) X(closedir) X(rewinddir) X(telldir) \
    X(seekdir) X(dirfd) \
    X(fopen) X(freopen)

/* Every wrapper declared with libc's exact prototype (a no-op redeclaration
 * where the wrapper carries libc's name). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"   /* readdir_r */
#define BRIXPOSIX_DECLARE(name) extern __typeof__(name) BRIXPOSIX_WRAP(name);
BRIXPOSIX_WRAPPED(BRIXPOSIX_DECLARE)
#pragma GCC diagnostic pop

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
 * The variable inherits libc's exact prototype via __typeof__(name); how
 * the symbol is found is the host's business (platform/preload.h). */
#define REAL(name)                                                      \
    static __typeof__(name) *real_##name = NULL;                        \
    if (real_##name == NULL) {                                          \
        real_##name = BRIXPOSIX_REAL_RESOLVE(name);                     \
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
/* A real FILE* over an already-open shadow fd (host stdio: fopencookie /
 * funopen; lib/platform/<host>/preload_stream.c).  On failure the fd is
 * closed here and NULL returned with errno: the caller only ever saw the
 * FILE*, so nothing else can. */
BRIXPOSIX_HIDDEN FILE     *brixposix_stream_open(int fd, const char *mode);

#endif /* BRIXPOSIX_INTERNAL_H */
