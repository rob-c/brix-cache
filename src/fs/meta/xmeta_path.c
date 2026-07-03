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
brix_xmeta_sidecar_path(char *dst, size_t cap, const char *path)
{
    int n = snprintf(dst, cap, "%s%s", path, BRIX_XMETA_PATH_SIDECAR);

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
brix_xmeta_path_load(const char *path, brix_xmeta_t *xm)
{
    char     sc[PATH_MAX];
    uint8_t *buf;
    ssize_t  n;
    int      fd, drc;

    if (path == NULL || xm == NULL) {
        errno = EINVAL;
        return BRIX_XMETA_ERR;
    }

    buf = malloc(BRIX_XMETA_PATH_XATTR_MAX);
    if (buf == NULL) {
        errno = ENOMEM;
        return BRIX_XMETA_ERR;
    }
    n = getxattr(path, BRIX_XMETA_PATH_XATTR, buf,
                 BRIX_XMETA_PATH_XATTR_MAX);
    if (n > 0) {
        drc = brix_xmeta_decode(buf, (size_t) n, xm);
        free(buf);
        return drc;
    }
    free(buf);

    if (brix_xmeta_sidecar_path(sc, sizeof(sc), path) != 0) {
        errno = ENAMETOOLONG;
        return BRIX_XMETA_ERR;
    }
    fd = open(sc, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return (errno == ENOENT) ? BRIX_XMETA_FOREIGN : BRIX_XMETA_ERR;
    }
    {
        struct stat stb;
        uint8_t    *fbuf;
        size_t      flen, got = 0;

        if (fstat(fd, &stb) != 0 || stb.st_size <= 0
            || (uint64_t) stb.st_size > BRIX_XMETA_MAX_SECTION)
        {
            close(fd);
            return BRIX_XMETA_FOREIGN;
        }
        flen = (size_t) stb.st_size;
        fbuf = malloc(flen);
        if (fbuf == NULL) {
            close(fd);
            errno = ENOMEM;
            return BRIX_XMETA_ERR;
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
            return BRIX_XMETA_FOREIGN;
        }
        drc = brix_xmeta_decode(fbuf, flen, xm);
        free(fbuf);
    }
    return drc;
}

int
brix_xmeta_path_save(const char *path, const brix_xmeta_t *xm)
{
    char     sc[PATH_MAX];
    uint8_t *buf = NULL;
    size_t   len = 0, put = 0;
    int      fd;

    if (path == NULL || xm == NULL) {
        errno = EINVAL;
        return BRIX_XMETA_ERR;
    }
    if (brix_xmeta_encode(xm, &buf, &len) != BRIX_XMETA_OK) {
        return BRIX_XMETA_ERR;
    }
    if (brix_xmeta_sidecar_path(sc, sizeof(sc), path) != 0) {
        free(buf);
        errno = ENAMETOOLONG;
        return BRIX_XMETA_ERR;
    }

    if (len <= BRIX_XMETA_PATH_XATTR_MAX
        && setxattr(path, BRIX_XMETA_PATH_XATTR, buf, len, 0) == 0)
    {
        free(buf);
        (void) unlink(sc);             /* one carrier: drop a stale sidecar */
        return BRIX_XMETA_OK;
    }
    if (len <= BRIX_XMETA_PATH_XATTR_MAX && !xmeta_path_xattr_unfit(errno)) {
        free(buf);
        return BRIX_XMETA_ERR;
    }

    fd = open(sc, O_WRONLY | O_CREAT | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
              0644);
    if (fd < 0) {
        free(buf);
        return BRIX_XMETA_ERR;
    }
    while (put < len) {
        ssize_t w = pwrite(fd, buf + put, len - put, (off_t) put);

        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            free(buf);
            close(fd);
            return BRIX_XMETA_ERR;
        }
        put += (size_t) w;
    }
    free(buf);
    if (ftruncate(fd, (off_t) len) != 0 || fdatasync(fd) != 0) {
        close(fd);
        return BRIX_XMETA_ERR;
    }
    if (close(fd) != 0) {
        return BRIX_XMETA_ERR;
    }
    (void) removexattr(path, BRIX_XMETA_PATH_XATTR);  /* one carrier */
    return BRIX_XMETA_OK;
}

int
brix_xmeta_path_remove(const char *path)
{
    char sc[PATH_MAX];

    if (path == NULL) {
        return BRIX_XMETA_OK;
    }
    (void) removexattr(path, BRIX_XMETA_PATH_XATTR);
    if (brix_xmeta_sidecar_path(sc, sizeof(sc), path) == 0) {
        (void) unlink(sc);
    }
    return BRIX_XMETA_OK;
}

int
brix_xmeta_path_lock(const char *path)
{
    char sc[PATH_MAX];
    int  fd;

    fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT
            || brix_xmeta_sidecar_path(sc, sizeof(sc), path) != 0)
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
brix_xmeta_path_unlock(int lockfd)
{
    if (lockfd >= 0) {
        (void) flock(lockfd, LOCK_UN);
        (void) close(lockfd);
    }
}
