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
        /* phase74-fp: ENOTSUP == EOPNOTSUPP on Linux so the operands are
         * equivalent HERE, but POSIX allows them to differ — the second test
         * is deliberate portability, not a typo. */
        || err == EOPNOTSUPP  /* NOLINT(misc-redundant-expression) */
#endif
        ;
}

/* ---- Try to load the record from the file's xattr carrier ----
 *
 * WHAT: Attempts to read and decode the metadata record from the preferred
 *   xattr carrier. Sets *done=1 and returns the decode result (or a hard error
 *   with errno set) when the outcome is definitive; sets *done=0 and returns
 *   BRIX_XMETA_OK when the xattr holds nothing, signalling the caller to fall
 *   back to the stock-readable sidecar.
 *
 * WHY: The xattr path is the fast, common case and is self-contained (alloc,
 *   read, decode, free). Isolating it keeps the loader orchestrator flat and
 *   lets the sidecar fallback be expressed as a single continue-or-return.
 *
 * HOW:
 *   1. Allocate the max-sized xattr scratch buffer; malloc failure is a
 *      definitive ENOMEM error.
 *   2. getxattr into it. A positive length is a present record: decode, free,
 *      and return the decode result as definitive.
 *   3. Any non-positive length means no record in the xattr: free, clear *done,
 *      and return OK so the caller tries the sidecar.
 */
static int
xmeta_path_load_from_xattr(const char *path, brix_xmeta_t *xm, int *done)
{
    uint8_t *buf;
    ssize_t  n;
    int      drc;

    *done = 1;
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
    *done = 0;                 /* nothing in the xattr — try the sidecar */
    return BRIX_XMETA_OK;
}

/* ---- Read and decode the record from an open sidecar fd ----
 *
 * WHAT: Reads the full contents of an already-open sidecar file and decodes it
 *   into *xm. Returns the decode result on success, BRIX_XMETA_FOREIGN when the
 *   sidecar is empty/oversized/short (not a valid record), or BRIX_XMETA_ERR
 *   (errno set) on allocation failure. Does NOT close fd — the caller owns it.
 *
 * WHY: The sidecar read is the bounded, syscall-heavy branch of the loader
 *   (stat, size-guard, alloc, interrupt-safe pread loop, decode). Pulling it
 *   into one helper keeps ownership of fd with the opener and the orchestrator
 *   free of the read machinery.
 *
 * HOW:
 *   1. fstat and reject empty or over-BRIX_XMETA_MAX_SECTION files as FOREIGN.
 *   2. Allocate a buffer sized to the file; malloc failure is an ENOMEM error.
 *   3. pread until full, retrying on EINTR and stopping on EOF/error.
 *   4. A short read is a truncated/foreign sidecar; otherwise decode and return.
 */
static int
xmeta_path_read_sidecar_fd(int fd, brix_xmeta_t *xm)
{
    struct stat stb;
    uint8_t    *fbuf;
    size_t      flen, got = 0;
    int         drc;

    if (fstat(fd, &stb) != 0 || stb.st_size <= 0
        || (uint64_t) stb.st_size > BRIX_XMETA_MAX_SECTION)
    {
        return BRIX_XMETA_FOREIGN;
    }
    flen = (size_t) stb.st_size;
    fbuf = malloc(flen);
    if (fbuf == NULL) {
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
    if (got != flen) {
        free(fbuf);
        return BRIX_XMETA_FOREIGN;
    }
    drc = brix_xmeta_decode(fbuf, flen, xm);
    free(fbuf);
    return drc;
}

/* ---- Load the unified metadata record for a path (xattr, then sidecar) ----
 *
 * WHAT: Loads the record into *xm, preferring the xattr carrier and falling
 *   back to the stock-readable sidecar. Returns BRIX_XMETA_OK, BRIX_XMETA_ERR
 *   (errno set), or BRIX_XMETA_FOREIGN (no valid record recorded).
 *
 * WHY: The two carriers must be tried in a fixed order with identical decode
 *   semantics; the orchestrator expresses that policy as a flat sequence while
 *   the per-carrier machinery lives in dedicated helpers.
 *
 * HOW:
 *   1. Reject NULL arguments with EINVAL.
 *   2. Try the xattr carrier; return its result if it was definitive.
 *   3. Otherwise build the sidecar path and open it; a missing sidecar is
 *      FOREIGN, any other open error is a hard error.
 *   4. Read and decode the sidecar, then close the fd and return the result.
 */
int
brix_xmeta_path_load(const char *path, brix_xmeta_t *xm)
{
    char sc[PATH_MAX];
    int  fd, drc, done;

    if (path == NULL || xm == NULL) {
        errno = EINVAL;
        return BRIX_XMETA_ERR;
    }

    drc = xmeta_path_load_from_xattr(path, xm, &done);
    if (done) {
        return drc;
    }

    if (brix_xmeta_sidecar_path(sc, sizeof(sc), path) != 0) {
        errno = ENAMETOOLONG;
        return BRIX_XMETA_ERR;
    }
    fd = open(sc, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return (errno == ENOENT) ? BRIX_XMETA_FOREIGN : BRIX_XMETA_ERR;
    }
    drc = xmeta_path_read_sidecar_fd(fd, xm);
    close(fd);
    return drc;
}

/* ---- Try to store the record in the file's xattr carrier ----
 *
 * WHAT: Attempts setxattr of the encoded record onto the preferred xattr
 *   carrier. Sets *done=1 and returns BRIX_XMETA_OK (stored) or BRIX_XMETA_ERR
 *   (a hard setxattr failure, errno from setxattr) when the outcome is
 *   definitive; sets *done=0 and returns BRIX_XMETA_OK when the record cannot
 *   ride in this xattr (too big, or setxattr failed with an "unfit" errno),
 *   signalling the caller to write the sidecar instead.
 *
 * WHY: The xattr-vs-sidecar decision is a small policy — oversized records and
 *   filesystems that reject xattrs must fall back rather than fail. Isolating it
 *   keeps that classification in one place and the saver orchestrator flat.
 *
 * HOW:
 *   1. Records over BRIX_XMETA_PATH_XATTR_MAX skip setxattr entirely (fall back).
 *   2. A successful setxattr is a definitive store.
 *   3. A setxattr failure that is not "unfit" is a definitive hard error.
 *   4. Any remaining case (too big, or an unfit errno) clears *done for fallback.
 */
static int
xmeta_path_save_to_xattr(const char *path, const uint8_t *buf, size_t len,
                         int *done)
{
    *done = 1;
    if (len <= BRIX_XMETA_PATH_XATTR_MAX
        && setxattr(path, BRIX_XMETA_PATH_XATTR, buf, len, 0) == 0)
    {
        return BRIX_XMETA_OK;
    }
    if (len <= BRIX_XMETA_PATH_XATTR_MAX && !xmeta_path_xattr_unfit(errno)) {
        return BRIX_XMETA_ERR;
    }
    *done = 0;                 /* xattr unfit — caller writes the sidecar */
    return BRIX_XMETA_OK;
}

/* ---- Write the encoded record to the stock-readable sidecar ----
 *
 * WHAT: Creates (or truncates) the sidecar at sc and writes len bytes from buf,
 *   then durably commits it. Returns BRIX_XMETA_OK on success or BRIX_XMETA_ERR
 *   on any open/write/truncate/sync/close failure. Does not free buf.
 *
 * WHY: The sidecar write is the bounded, syscall-heavy fallback path (create,
 *   interrupt-safe pwrite loop, truncate, fdatasync, close). Pulling it into one
 *   helper keeps the durability sequence together and the orchestrator flat.
 *
 * HOW:
 *   1. Open the sidecar 0600 O_CREAT (see the SECURITY note below).
 *   2. pwrite until the whole buffer is written, retrying on EINTR and failing
 *      on any short/zero write.
 *   3. ftruncate to len (drop any prior tail), fdatasync, then close, mapping
 *      any failure to a hard error.
 */
static int
xmeta_path_write_sidecar(const char *sc, const uint8_t *buf, size_t len)
{
    size_t put = 0;
    int    fd;

    /* SECURITY: the metadata sidecar (cache .cinfo residency bitmap / CSI record)
     * is created and read AS THE WORKER (server-managed sidecar, see meta.c
     * vfs-seam-allow; CSI verify is a backend op). 0600 (not 0644) so it cannot
     * leak cache residency / integrity metadata to a mapped low-priv uid on a
     * shared filesystem. Safe: with impersonation=map the master is root and
     * reads any-owner sidecar; without impersonation the worker owns and reads it. */
    fd = open(sc, O_WRONLY | O_CREAT | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0) {
        return BRIX_XMETA_ERR;
    }
    while (put < len) {
        ssize_t w = pwrite(fd, buf + put, len - put, (off_t) put);

        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            close(fd);
            return BRIX_XMETA_ERR;
        }
        put += (size_t) w;
    }
    if (ftruncate(fd, (off_t) len) != 0 || fdatasync(fd) != 0) {
        close(fd);
        return BRIX_XMETA_ERR;
    }
    if (close(fd) != 0) {
        return BRIX_XMETA_ERR;
    }
    return BRIX_XMETA_OK;
}

/* ---- Save the unified metadata record for a path (xattr, else sidecar) ----
 *
 * WHAT: Encodes *xm and stores it in exactly one carrier — the xattr when it
 *   fits, otherwise the stock-readable sidecar — dropping the other carrier so
 *   only one copy survives. Returns BRIX_XMETA_OK or BRIX_XMETA_ERR (errno set).
 *
 * WHY: "One carrier" is the invariant: a successful xattr write removes any
 *   stale sidecar and a successful sidecar write removes the xattr. The
 *   orchestrator owns the encoded buffer and enforces that single-copy rule
 *   while the two carriers are handled by dedicated helpers.
 *
 * HOW:
 *   1. Reject NULL arguments with EINVAL, then encode the record and build the
 *      sidecar path.
 *   2. Try the xattr carrier; if definitive, free the buffer, unlink the stale
 *      sidecar on success, and return that result.
 *   3. Otherwise write the sidecar, free the buffer, and on success remove the
 *      now-superseded xattr before returning OK.
 */
int
brix_xmeta_path_save(const char *path, const brix_xmeta_t *xm)
{
    char     sc[PATH_MAX];
    uint8_t *buf = NULL;
    size_t   len = 0;
    int      rc, done;

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

    rc = xmeta_path_save_to_xattr(path, buf, len, &done);
    if (done) {
        free(buf);
        if (rc == BRIX_XMETA_OK) {
            (void) unlink(sc);         /* one carrier: drop a stale sidecar */
        }
        return rc;
    }

    rc = xmeta_path_write_sidecar(sc, buf, len);
    free(buf);
    if (rc != BRIX_XMETA_OK) {
        return rc;
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
                  0600);   /* worker-owned lock sidecar; 0600 (see path_save) */
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
