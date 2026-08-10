/*
 * brixposix_stat.c — the preload shim's stat/access family (§ split from
 * brixposix_preload.c for the 600-line file gate, 2026-08-10). Behaviour-
 * identical; shares state with the core via brixposix_internal.h.
 *
 * Interposes stat/lstat/fstat/fstatat/access(+64 variants)/statx: a path under
 * the BRIX_VMP prefix is answered from a remote kXR_stat; everything else
 * falls through to the real libc symbol.
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
stat(const char *path, struct stat *stbuf)
{
    char remote[XRDC_PATH_MAX];
    REAL(stat);
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);
    }
    return real_stat(path, stbuf);
}

int
lstat(const char *path, struct stat *stbuf)
{
    char remote[XRDC_PATH_MAX];
    REAL(lstat);
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);   /* no symlinks in the export */
    }
    return real_lstat(path, stbuf);
}

int
fstat(int fd, struct stat *stbuf)
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
fstatat(int dirfd, const char *path, struct stat *stbuf, int flags)
{
    char remote[XRDC_PATH_MAX];
    REAL(fstatat);
    if (path[0] == '/' && map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, stbuf);
    }
    return real_fstatat(dirfd, path, stbuf, flags);
}

int
access(const char *path, int mode)
{
    char        remote[XRDC_PATH_MAX];
    struct stat sb;
    REAL(access);
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, &sb);   /* existence/readability check */
    }
    return real_access(path, mode);
}

/*
 * The *64 (LFS) variants. Tools built with _FILE_OFFSET_BITS=64 (coreutils, etc.)
 * call stat64/lstat64/fstat64/fstatat64, not the plain names, so those must be
 * interposed too or a pre-open stat() of a remote path would wrongly ENOENT. On
 * this platform struct stat and struct stat64 are layout-identical, so the remote
 * fill is shared via a cast (guarded by the static assert below).
 */
_Static_assert(sizeof(struct stat) == sizeof(struct stat64),
               "struct stat / stat64 layout differ; *64 stat shims need rework");

int
stat64(const char *path, struct stat64 *stbuf)
{
    char remote[XRDC_PATH_MAX];
    REAL(stat64);
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, (struct stat *) stbuf);
    }
    return real_stat64(path, stbuf);
}

int
lstat64(const char *path, struct stat64 *stbuf)
{
    char remote[XRDC_PATH_MAX];
    REAL(lstat64);
    if (map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, (struct stat *) stbuf);
    }
    return real_lstat64(path, stbuf);
}

int
fstat64(int fd, struct stat64 *stbuf)
{
    xfs_slot *s;
    REAL(fstat64);
    s = slot_of(fd);
    if (s == NULL) {
        return real_fstat64(fd, stbuf);
    }
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = (off_t) s->size;
    return 0;
}

int
fstatat64(int dirfd, const char *path, struct stat64 *stbuf, int flags)
{
    char remote[XRDC_PATH_MAX];
    REAL(fstatat64);
    if (path[0] == '/' && map_path(path, remote, sizeof(remote))) {
        return remote_stat(remote, (struct stat *) stbuf);
    }
    return real_fstatat64(dirfd, path, stbuf, flags);
}

/*
 * statx() is what modern coreutils (ls, stat, find, du) actually call. Without
 * interposing it, those tools would statx the real (absent) local path and
 * ENOENT. We fill the common fields (type/mode/nlink/size/mtime); the caller's
 * requested `mask` is satisfied for what XRootD can report.
 */
int
statx(int dirfd, const char *path, int flags, unsigned int mask,
      struct statx *stxbuf)
{
    char          remote[XRDC_PATH_MAX];
    brix_status   st;
    brix_statinfo si;
    int           rc;
    REAL(statx);

    (void) mask;
    if (path[0] != '/' || !map_path(path, remote, sizeof(remote))) {
        return real_statx(dirfd, path, flags, mask, stxbuf);
    }
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
    /* Map through fill_stat (= the shared posix_map helper) so statx and stat
     * can never disagree, then translate to statx fields. STATX_INO is in the
     * answered mask now: the stable server file id is what lets ls -i / find
     * -samefile / rsync see distinct files instead of one shared identity. */
    {
        struct stat mapped;

        fill_stat(&si, &mapped);
        memset(stxbuf, 0, sizeof(*stxbuf));
        stxbuf->stx_mask = STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_SIZE
                           | STATX_MTIME | STATX_INO;
        stxbuf->stx_mode    = (uint16_t) mapped.st_mode;
        stxbuf->stx_nlink   = (uint32_t) mapped.st_nlink;
        stxbuf->stx_size    = (uint64_t) mapped.st_size;
        stxbuf->stx_ino     = (uint64_t) mapped.st_ino;
        stxbuf->stx_blksize = (uint32_t) mapped.st_blksize;
        stxbuf->stx_blocks  = (uint64_t) mapped.st_blocks;
        stxbuf->stx_mtime.tv_sec = mapped.st_mtime;
        stxbuf->stx_atime.tv_sec = mapped.st_atime;
        stxbuf->stx_ctime.tv_sec = mapped.st_ctime;
    }
    return 0;
}
