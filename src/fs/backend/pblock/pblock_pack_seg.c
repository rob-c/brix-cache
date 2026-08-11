/*
 * pblock_pack_seg.c — phase-88 W2: low-level segment-file helpers for the
 * packed small-blob arena. Split out of pblock_pack.c (file-size cap); see
 * pblock_pack_internal.h for the seam and pblock_pack.c for the catalog/admit
 * logic that drives these. ngx-free (libc only); BRIX_HAVE_SQLITE-gated so the
 * arena TUs compile as a unit.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "pblock_store.h"
#include "pblock_pack_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/file.h>

/* pack_pread_full — read exactly len bytes at off (EINTR-safe); 0 or -1. */
int
pack_pread_full(int fd, void *buf, size_t len, off_t off)
{
    char   *cursor = buf;
    size_t  got = 0;

    while (got < len) {
        ssize_t n = pread(fd, cursor + got, len - got, off + (off_t) got);

        if (n < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        if (n == 0) {
            errno = EIO;           /* a record must never end early */
            return -1;
        }
        got += (size_t) n;
    }
    return 0;
}

/* pack_pwrite_full — write exactly len bytes at off (EINTR-safe); 0 or -1. */
int
pack_pwrite_full(int fd, const void *buf, size_t len, off_t off)
{
    const char *cursor = buf;
    size_t      done = 0;

    while (done < len) {
        ssize_t n = pwrite(fd, cursor + done, len - done, off + (off_t) done);

        if (n < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        done += (size_t) n;
    }
    return 0;
}

/* pack_seg_path — "<root>/pack/seg-<n>.dat" into out[cap]; 0 or -1. */
int
pack_seg_path(const pblock_state_t *st, int64_t seg, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/pack/seg-%lld.dat", st->root,
                     (long long) seg);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* pack_lock — take the arena append/reap lock (pack/.lock, flock LOCK_EX).
 * Returns the held fd, or -1/errno. */
int
pack_lock(const pblock_state_t *st)
{
    char lockp[PATH_MAX];
    int  fd;
    int  n = snprintf(lockp, sizeof(lockp), "%s/pack/.lock", st->root);

    if (n <= 0 || (size_t) n >= sizeof(lockp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open(lockp, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }
    if (flock(fd, LOCK_EX) != 0) {
        int err = errno;

        close(fd);
        errno = err;
        return -1;
    }
    return fd;
}

/* pack_active_seg — highest existing segment number (0 when none). Scan the
 * pack/ dir; called only under the arena lock, where the answer is stable. */
int64_t
pack_active_seg(const pblock_state_t *st)
{
    char           dirp[PATH_MAX];
    DIR           *dir;
    struct dirent *ent;
    int64_t        hi = 0;

    if (snprintf(dirp, sizeof(dirp), "%s/pack", st->root) >= (int) sizeof(dirp)) {
        return 0;
    }
    dir = opendir(dirp);
    if (dir == NULL) {
        return 0;
    }
    while ((ent = readdir(dir)) != NULL) {
        long long seg;

        if (sscanf(ent->d_name, "seg-%lld.dat", &seg) == 1
            && (int64_t) seg > hi)
        {
            hi = (int64_t) seg;
        }
    }
    closedir(dir);
    return hi;
}

#endif /* BRIX_HAVE_SQLITE */
