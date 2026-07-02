/*
 * fs/meta/xmeta_path.c — raw-path carrier for the unified metadata record
 * (xattr preferred, stock-readable sidecar fallback). See xmeta_path.h.
 */

#include "xmeta_path.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

int
xrootd_xmeta_sidecar_path(char *dst, size_t cap, const char *path)
{
    int n = snprintf(dst, cap, "%s%s", path, XROOTD_XMETA_PATH_SIDECAR);

    return (n < 0 || (size_t) n >= cap) ? -1 : 0;
}

/* "the record cannot ride in this file's xattr" — fall back, don't fail */
static int
xmeta_path_xattr_unfit(int err)
{
    return err == E2BIG || err == ERANGE || err == ENOSPC || err == ENOTSUP
        || err == EACCES || err == EPERM || err == ENOENT
#ifdef EOPNOTSUPP
        || err == EOPNOTSUPP
#endif
        ;
}

int
xrootd_xmeta_path_load(const char *path, xrootd_xmeta_t *xm)
{
    char     sc[PATH_MAX];
    uint8_t *buf;
    ssize_t  n;
    int      fd, drc;

    if (path == NULL || xm == NULL) {
        errno = EINVAL;
        return XROOTD_XMETA_ERR;
    }

    buf = malloc(XROOTD_XMETA_PATH_XATTR_MAX);
    if (buf == NULL) {
        errno = ENOMEM;
        return XROOTD_XMETA_ERR;
    }
    n = getxattr(path, XROOTD_XMETA_PATH_XATTR, buf,
                 XROOTD_XMETA_PATH_XATTR_MAX);
    if (n > 0) {
        drc = xrootd_xmeta_decode(buf, (size_t) n, xm);
        free(buf);
        return drc;
    }
    free(buf);

    if (xrootd_xmeta_sidecar_path(sc, sizeof(sc), path) != 0) {
        errno = ENAMETOOLONG;
        return XROOTD_XMETA_ERR;
    }
    fd = open(sc, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return (errno == ENOENT) ? XROOTD_XMETA_FOREIGN : XROOTD_XMETA_ERR;
    }
    {
        struct stat stb;
        uint8_t    *fbuf;
        size_t      flen, got = 0;

        if (fstat(fd, &stb) != 0 || stb.st_size <= 0
            || (uint64_t) stb.st_size > XROOTD_XMETA_MAX_SECTION)
        {
            close(fd);
            return XROOTD_XMETA_FOREIGN;
        }
        flen = (size_t) stb.st_size;
        fbuf = malloc(flen);
        if (fbuf == NULL) {
            close(fd);
            errno = ENOMEM;
            return XROOTD_XMETA_ERR;
        }
        while (got < flen) {
            ssize_t r = pread(fd, fbuf + got, flen - got, (off_t) got);

            if (r < 0 && errno == EINTR) {
                continue;
            }
            if (r <= 0) {
                break;
            }
            got += (size_t) r;
        }
        close(fd);
        if (got != flen) {
            free(fbuf);
            return XROOTD_XMETA_FOREIGN;
        }
        drc = xrootd_xmeta_decode(fbuf, flen, xm);
        free(fbuf);
    }
    return drc;
}

int
xrootd_xmeta_path_save(const char *path, const xrootd_xmeta_t *xm)
{
    char     sc[PATH_MAX];
    uint8_t *buf = NULL;
    size_t   len = 0, put = 0;
    int      fd;

    if (path == NULL || xm == NULL) {
        errno = EINVAL;
        return XROOTD_XMETA_ERR;
    }
    if (xrootd_xmeta_encode(xm, &buf, &len) != XROOTD_XMETA_OK) {
        return XROOTD_XMETA_ERR;
    }
    if (xrootd_xmeta_sidecar_path(sc, sizeof(sc), path) != 0) {
        free(buf);
        errno = ENAMETOOLONG;
        return XROOTD_XMETA_ERR;
    }

    if (len <= XROOTD_XMETA_PATH_XATTR_MAX
        && setxattr(path, XROOTD_XMETA_PATH_XATTR, buf, len, 0) == 0)
    {
        free(buf);
        (void) unlink(sc);             /* one carrier: drop a stale sidecar */
        return XROOTD_XMETA_OK;
    }
    if (len <= XROOTD_XMETA_PATH_XATTR_MAX && !xmeta_path_xattr_unfit(errno)) {
        free(buf);
        return XROOTD_XMETA_ERR;
    }

    fd = open(sc, O_WRONLY | O_CREAT | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
              0644);
    if (fd < 0) {
        free(buf);
        return XROOTD_XMETA_ERR;
    }
    while (put < len) {
        ssize_t w = pwrite(fd, buf + put, len - put, (off_t) put);

        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            free(buf);
            close(fd);
            return XROOTD_XMETA_ERR;
        }
        put += (size_t) w;
    }
    free(buf);
    if (ftruncate(fd, (off_t) len) != 0 || fdatasync(fd) != 0) {
        close(fd);
        return XROOTD_XMETA_ERR;
    }
    if (close(fd) != 0) {
        return XROOTD_XMETA_ERR;
    }
    (void) removexattr(path, XROOTD_XMETA_PATH_XATTR);  /* one carrier */
    return XROOTD_XMETA_OK;
}

int
xrootd_xmeta_path_remove(const char *path)
{
    char sc[PATH_MAX];

    if (path == NULL) {
        return XROOTD_XMETA_OK;
    }
    (void) removexattr(path, XROOTD_XMETA_PATH_XATTR);
    if (xrootd_xmeta_sidecar_path(sc, sizeof(sc), path) == 0) {
        (void) unlink(sc);
    }
    return XROOTD_XMETA_OK;
}

int
xrootd_xmeta_path_lock(const char *path)
{
    char sc[PATH_MAX];
    int  fd;

    fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT
            || xrootd_xmeta_sidecar_path(sc, sizeof(sc), path) != 0)
        {
            return -1;
        }
        fd = open(sc, O_RDWR | O_CREAT | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
                  0644);
        if (fd < 0) {
            return -1;
        }
    }
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

void
xrootd_xmeta_path_unlock(int lockfd)
{
    if (lockfd >= 0) {
        (void) flock(lockfd, LOCK_UN);
        (void) close(lockfd);
    }
}
