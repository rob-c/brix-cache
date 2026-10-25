/*
 * brixposix_stat.c — the preload shim's stat/access family (§ split from
 * brixposix_preload.c for the 600-line file gate, 2026-08-10). Behaviour-
 * identical; shares state with the core via brixposix_internal.h.
 *
 * Interposes stat/lstat/fstat/fstatat/access: a path under the BRIX_VMP prefix
 * is answered from a remote kXR_stat; everything else falls through to the
 * real libc symbol. The glibc-only *64 spellings and statx forward here from
 * lib/platform/linux/preload_lfs.c.
 */
#include "brixposix_internal.h"
#include "posix/posix_map.h"   /* brix_statinfo_to_stat via fill_stat */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* stat family + access                                                */

static int
remote_stat(const char *remote, struct stat *stbuf)
{
    brix_status   st;
    brix_statinfo si;
    int           rc;

    pthread_mutex_lock(&g_lock);
    if (ensure_conn() != 0) {
        pthread_mutex_unlock(&g_lock);
        errno = EIO;
        return -1;
    }
    brix_status_clear(&st);
    rc = brix_stat(&g_conn, remote, &si, &st);
    pthread_mutex_unlock(&g_lock);
    if (rc != 0) {
        errno = -brix_kxr_to_errno(&st);
        return -1;
    }
    fill_stat(&si, stbuf);
    return 0;
}

/* WHAT: Route stat through the shared prefix policy or real host ABI.
 * WHY: Legacy glibc entry points must bypass its inline stat redirects.
 * HOW: Map once, then use remote_stat or the host's original libc entry. */
int
brixposix_stat_impl(const char *path, struct stat *stbuf)
{
    char remote[XRDC_PATH_MAX];
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);
    }
    return brix_plat_preload_stat(path, stbuf);
}

/* WHAT: The exported stat wrapper; returns the shared body's status.
 * WHY: Keep one policy body for modern and legacy libc ABIs.
 * HOW: Delegate without calling glibc's inline stat entry. */
int
BRIXPOSIX_WRAP(stat)(const char *path, struct stat *stbuf)
{
    return brixposix_stat_impl(path, stbuf);
}

/* WHAT: Route lstat without duplicating remote metadata construction.
 * WHY: A local, non-prefix symlink must retain real libc semantics.
 * HOW: Map once, then use remote_stat or the real host lstat. */
int
brixposix_lstat_impl(const char *path, struct stat *stbuf)
{
    char remote[XRDC_PATH_MAX];
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);   /* no symlinks in the export */
    }
    return brix_plat_preload_lstat(path, stbuf);
}

/* WHAT: Export lstat with the shared prefix-policy body.
 * WHY: Keep legacy and modern lstat results identical.
 * HOW: Delegate directly to the internal implementation. */
int
BRIXPOSIX_WRAP(lstat)(const char *path, struct stat *stbuf)
{
    return brixposix_lstat_impl(path, stbuf);
}

/* WHAT: Describe a shadow descriptor, or preserve real local fstat.
 * WHY: Older libc's __fxstat callers must recognize virtual descriptors.
 * HOW: Look up the existing slot; otherwise use the real host ABI. */
int
brixposix_fstat_impl(int fd, struct stat *stbuf)
{
    xfs_slot *s;
    s = slot_of(fd);
    if (s == NULL) {
        return brix_plat_preload_fstat(fd, stbuf);
    }
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = (off_t) s->size;
    return 0;
}

/* WHAT: Export fstat using the common shadow-descriptor implementation.
 * WHY: Avoid libc inline redirects between compatibility entry points.
 * HOW: Delegate to the internal body. */
int
BRIXPOSIX_WRAP(fstat)(int fd, struct stat *stbuf)
{
    return brixposix_fstat_impl(fd, stbuf);
}

/* WHAT: Route absolute mapped paths and preserve other fstatat semantics.
 * WHY: Relative dirfd operations outside the mapping remain libc-owned.
 * HOW: Map only absolute prefix paths, otherwise call the real host ABI. */
int
brixposix_fstatat_impl(int dirfd, const char *path, struct stat *stbuf, int flags)
{
    char remote[XRDC_PATH_MAX];
    if (path[0] == '/' && map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);
    }
    return brix_plat_preload_fstatat(dirfd, path, stbuf, flags);
}

/* WHAT: Export fstatat using the shared path-routing implementation.
 * WHY: Modern and legacy callers must pass the same mapping policy.
 * HOW: Delegate directly, retaining dirfd and flags. */
int
BRIXPOSIX_WRAP(fstatat)(int dirfd, const char *path, struct stat *stbuf, int flags)
{
    return brixposix_fstatat_impl(dirfd, path, stbuf, flags);
}

int
BRIXPOSIX_WRAP(access)(const char *path, int mode)
{
    char        remote[XRDC_PATH_MAX];
    struct stat sb;
    REAL(access);
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, &sb);   /* existence/readability check */
    }
    return real_access(path, mode);
}
