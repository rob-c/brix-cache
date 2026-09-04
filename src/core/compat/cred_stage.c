/*
 * cred_stage.c — private staging area for short-lived credential material.
 * See cred_stage.h for the rationale (CWE-377 co-tenant race, fail-closed).
 *
 * Pure libc so it links into both the stream module (native TPC, GSI proxy) and
 * the HTTP module (WebDAV TPC) and is unit-testable without nginx.
 */

#include "cred_stage.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>          /* getentropy */
#include <sys/types.h>
#include <sys/stat.h>

/* Per-uid staging root on tmpfs.  /dev/shm is 1777 (sticky, world-writable), so
 * every uid can create its OWN 0700 subdirectory here that no other uid can enter
 * or delete; the security boundary is that dir's mode + ownership, checked below.
 * Per-uid naming keeps distinct workers/users from tripping over each other's dir
 * ownership on a shared host. */
#define BRIX_CRED_STAGE_BASE "/dev/shm/brix-creds"

/* REQUIRE a real directory, owned by us, with no group/other access. A path
 * that fails any of these (a foreign squatter, a loosened mode, a symlink) is
 * unsafe for a secret — fail closed rather than trust it. Shared by BOTH
 * credential arms (phase-108 C11.2): the persistent destination dir gets
 * exactly the scrutiny the volatile staging dir always had, re-checked on
 * every call. */
static int
cred_dir_check(const char *dir)
{
    struct stat st;

    if (lstat(dir, &st) != 0) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)
        || st.st_uid != geteuid()
        || (st.st_mode & 0077) != 0)
    {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int
brix_cred_stage_dir(char *out, size_t outsz)
{
    char  dir[64];
    int   n;

    n = snprintf(dir, sizeof(dir), "%s.%u",
                 BRIX_CRED_STAGE_BASE, (unsigned) geteuid());
    if (n < 0 || (size_t) n >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    if (cred_dir_check(dir) != 0) {
        return -1;
    }

    if ((size_t) n + 1 > outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, dir, (size_t) n + 1);
    return 0;
}

/* ---- The shared credential-write engine (phase-108 C11) ---- */

/* Create a fresh 0600 file "<base><8 hex chars>" with the full C11.2 flag
 * set. O_CREAT|O_EXCL never follows a symlink and refuses a squatter (even a
 * dangling link answers EEXIST); a fresh random suffix per attempt makes the
 * EEXIST retry safe. Returns the fd with the path in `path`, or -1. */
static int
cred_create_excl(const char *base, char *path, size_t pathsz)
{
    unsigned char  rnd[4];
    int            attempt, fd, n;

    for (attempt = 0; attempt < 16; attempt++) {
        if (getentropy(rnd, sizeof(rnd)) != 0) {
            return -1;
        }
        n = snprintf(path, pathsz, "%s%02x%02x%02x%02x",
                     base, rnd[0], rnd[1], rnd[2], rnd[3]);
        if (n < 0 || (size_t) n >= pathsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        fd = open(path,
                  O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC,
                  S_IRUSR | S_IWUSR);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EEXIST) {
            return -1;
        }
    }
    errno = EEXIST;
    return -1;
}

/* EINTR-safe full-length write; a short write that never completes is an
 * error, never a silent truncation of a secret. */
static int
cred_write_full(int fd, const void *bytes, size_t len)
{
    const unsigned char  *p = bytes;
    size_t                off = 0;

    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

/* Reap a failed in-flight temp file: close, unlink, preserve errno. */
static int
cred_fail_fd(int fd, const char *path)
{
    int saved = errno;

    (void) close(fd);
    (void) unlink(path);
    errno = saved;
    return -1;
}

/* The publish durability barrier: a rename is not durable until its parent
 * directory is. Open the dir itself and fsync it; close is checked — an
 * unreported barrier failure would be a silent durability downgrade. */
static int
cred_dir_flush(const char *dir)
{
    int  fd, saved;

    fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (fsync(fd) != 0) {
        saved = errno;
        (void) close(fd);
        errno = saved;
        return -1;
    }
    return close(fd) == 0 ? 0 : -1;
}

/* A basename component for a credential file: non-empty, no '/', not a dot
 * dir — anything else could walk the write out of the claimed directory. */
static int
cred_name_ok(const char *s)
{
    if (s == NULL || s[0] == '\0' || strchr(s, '/') != NULL) {
        return 0;
    }
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) {
        return 0;
    }
    return 1;
}

/* VOLATILE arm: the temp file under the private tmpfs staging dir IS the
 * product; the caller consumes and unlinks it. Deliberately NO fsync — the
 * §3.3 carve-out: durability for a secret that must not survive reboot is an
 * anti-goal, and tmpfs has nothing to sync to anyway. */
static int
cred_write_volatile(const brix_cred_write_req_t *req, const void *bytes,
                    size_t len, char *path_out, size_t path_outsz)
{
    char  dir[64];
    char  base[192];
    int   fd, n, saved;

    if (brix_cred_stage_dir(dir, sizeof(dir)) != 0) {
        return -1;                          /* fail closed — never /tmp */
    }

    n = snprintf(base, sizeof(base), "%s/%s", dir, req->prefix);
    if (n < 0 || (size_t) n >= sizeof(base)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    fd = cred_create_excl(base, path_out, path_outsz);
    if (fd < 0) {
        return -1;
    }

    /* Defensive: pin 0600 regardless of umask/platform open() behaviour. */
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0
        || cred_write_full(fd, bytes, len) != 0)
    {
        return cred_fail_fd(fd, path_out);
    }

    if (close(fd) != 0) {                   /* close IS a write error here */
        saved = errno;
        (void) unlink(path_out);
        errno = saved;
        return -1;
    }
    return 0;
}

/* PERSISTENT arm: stage "<dir>/.<name>.<random>", fsync the data, publish by
 * rename to "<dir>/<name>", then flush the parent. The destination dir is
 * held to the SAME standard as the staging dir (cred_dir_check): a
 * group-readable credential dir is refused with EPERM, not tolerated. */
static int
cred_write_persistent(const brix_cred_write_req_t *req, const void *bytes,
                      size_t len, char *path_out, size_t path_outsz)
{
    char  base[PATH_MAX];
    char  tmp[PATH_MAX];
    int   fd, n, saved;

    if (mkdir(req->dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    if (cred_dir_check(req->dir) != 0) {
        return -1;
    }

    /* Compose the final path first so a too-small caller buffer is refused
     * before any file exists. */
    n = snprintf(path_out, path_outsz, "%s/%s", req->dir, req->name);
    if (n < 0 || (size_t) n >= path_outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }

    n = snprintf(base, sizeof(base), "%s/.%s.", req->dir, req->name);
    if (n < 0 || (size_t) n >= sizeof(base)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    fd = cred_create_excl(base, tmp, sizeof(tmp));
    if (fd < 0) {
        return -1;
    }

    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0
        || cred_write_full(fd, bytes, len) != 0
        || fsync(fd) != 0)
    {
        return cred_fail_fd(fd, tmp);
    }

    if (close(fd) != 0) {                   /* close IS a write error here */
        saved = errno;
        (void) unlink(tmp);
        errno = saved;
        return -1;
    }

    if (rename(tmp, path_out) != 0) {
        saved = errno;
        (void) unlink(tmp);
        errno = saved;
        return -1;
    }

    /* A barrier failure after rename is reported but the published file is
     * NOT unlinked: the rename may have replaced a live credential, and
     * destroying it would be worse than the lost durability barrier. */
    return cred_dir_flush(req->dir);
}

int
brix_cred_write_engine(const brix_cred_write_req_t *req, const void *bytes,
                       size_t len, char *path_out, size_t path_outsz)
{
    if (req == NULL || path_out == NULL || path_outsz == 0
        || (bytes == NULL && len > 0)
        || (unsigned) req->arm >= BRIX_CRED_ARM_COUNT
        || (unsigned) req->kind >= BRIX_CRED_KIND_COUNT)
    {
        errno = EINVAL;
        return -1;
    }

    if (req->arm == BRIX_CRED_ARM_VOLATILE) {
        if (!cred_name_ok(req->prefix)) {
            errno = EINVAL;
            return -1;
        }
        return cred_write_volatile(req, bytes, len, path_out, path_outsz);
    }

    if (req->dir == NULL || req->dir[0] == '\0' || !cred_name_ok(req->name)) {
        errno = EINVAL;
        return -1;
    }
    return cred_write_persistent(req, bytes, len, path_out, path_outsz);
}

/* The pre-C11 entry point, kept verbatim for its six callers: a thin wrapper
 * over the VOLATILE arm (kind is audit vocabulary only and these sites are
 * audited/accounted at their own protocol planes, not here — the ngx-aware
 * brix_cred_write in cred_write.c is where the domain claim and audit line
 * live). */
int
brix_cred_stage_write(const char *prefix, const void *bytes, size_t len,
                      char *path_out, size_t path_outsz)
{
    brix_cred_write_req_t req;

    memset(&req, 0, sizeof(req));
    req.arm = BRIX_CRED_ARM_VOLATILE;
    req.kind = BRIX_CRED_KIND_BEARER;
    req.prefix = prefix;

    return brix_cred_write_engine(&req, bytes, len, path_out, path_outsz);
}
