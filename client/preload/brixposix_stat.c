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

int
BRIXPOSIX_WRAP(stat)(const char *path, struct stat *stbuf)
{
    char remote[XRDC_PATH_MAX];
    REAL(stat);
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);
    }
    return real_stat(path, stbuf);
}

int
BRIXPOSIX_WRAP(lstat)(const char *path, struct stat *stbuf)
{
    char remote[XRDC_PATH_MAX];
    REAL(lstat);
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);   /* no symlinks in the export */
    }
    return real_lstat(path, stbuf);
}

int
BRIXPOSIX_WRAP(fstat)(int fd, struct stat *stbuf)
{
    xfs_slot *s;
    REAL(fstat);
    s = slot_of(fd);
    if (s == NULL) {
        return real_fstat(fd, stbuf);
    }
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = (off_t) s->size;
    return 0;
}

int
BRIXPOSIX_WRAP(fstatat)(int dirfd, const char *path, struct stat *stbuf, int flags)
{
    char remote[XRDC_PATH_MAX];
    REAL(fstatat);
    if (path[0] == '/' && map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);
    }
    return real_fstatat(dirfd, path, stbuf, flags);
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
