/*
 * brixposix_preload.c — an LD_PRELOAD shim that routes POSIX reads of a configured
 * path prefix to an XRootD root:// export via libbrix.
 *
 * WHAT: Interpose open/read/pread/lseek/close, the stat family (incl. statx and
 *       the LFS *64 variants) and access on libc. Any
 *       path under the prefix named by $BRIX_VMP is served from a remote XRootD
 *       server; every other path passes straight through to the real libc call.
 * WHY:  Legacy tools that only know POSIX paths (cat, md5sum, ls, analysis jobs)
 *       can read remote XRootD data with no recompile and NO libXrdCl/XrdPosix --
 *       just LD_PRELOAD=libbrixposix_preload.so BRIX_VMP=/xrd=root://host:port/.
 * HOW:  $BRIX_VMP = "<localprefix>=root://host[:port][/base]". A path that
 *       starts with <localprefix> is rewritten to the remote logical path and
 *       opened through a single lazily-connected libbrix session (one request in
 *       flight, mutex-guarded). Remote descriptors live in a shadow fd table at
 *       fds >= XFS_FD_BASE so read/lseek/close/fstat can tell them apart from
 *       real fds. Real libc symbols are resolved with dlsym(RTLD_NEXT) via the
 *       __typeof__-based REAL() helper (so each wrapper inherits libc's prototype).
 *
 * Scope (first cut): the READ path. Files opened for write under the prefix fall
 * through to libc (a documented follow-up), as do fopen/mmap and the legacy
 * __xstat() routing (modern glibc exports stat/lstat/fstat as real symbols, which
 * we interpose directly).
 *
 * Clean-room: composes the public libbrix API + dlsym only; no XrdPosix code.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* RTLD_NEXT, *64 variants (the build also passes -D_GNU_SOURCE) */
#endif
#include "brix.h"
#include "posix/posix_map.h"    /* brix_statinfo_to_stat — the ONE statinfo→stat map */
#include "brixposix_internal.h" /* shared shim state/helpers (hidden visibility) */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* configuration (BRIX_VMP) + the lazily-connected session           */

static pthread_once_t  g_once = PTHREAD_ONCE_INIT;
BRIXPOSIX_HIDDEN pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int       g_enabled;            /* BRIX_VMP parsed and usable */
static char      g_prefix[256];        /* local path prefix, e.g. "/xrd" */
static size_t    g_prefix_len;
static brix_url  g_url;                 /* remote endpoint + base path */
static char      g_base[XRDC_PATH_MAX]; /* remote base ("" when "/") */

BRIXPOSIX_HIDDEN brix_conn g_conn;
static int       g_connected;

static void
parse_vmp(void)
{
    const char *vmp = getenv("BRIX_VMP");
    const char *eq;
    char        url[512];
    brix_status st;

    if (vmp == NULL || vmp[0] == '\0') {
        return;
    }
    eq = strchr(vmp, '=');
    if (eq == NULL || (size_t) (eq - vmp) >= sizeof(g_prefix)) {
        return;
    }
    memcpy(g_prefix, vmp, (size_t) (eq - vmp));
    g_prefix[eq - vmp] = '\0';
    g_prefix_len = strlen(g_prefix);
    /* strip a trailing slash on the prefix so "/xrd" and "/xrd/" both work */
    while (g_prefix_len > 1 && g_prefix[g_prefix_len - 1] == '/') {
        g_prefix[--g_prefix_len] = '\0';
    }

    snprintf(url, sizeof(url), "%s", eq + 1);
    brix_status_clear(&st);
    if (brix_endpoint_parse(url, &g_url, &st) != 0) {
        return;
    }
    if (g_url.path[0] != '\0' && strcmp(g_url.path, "/") != 0) {
        size_t bl;
        snprintf(g_base, sizeof(g_base), "%s", g_url.path);
        bl = strlen(g_base);
        while (bl > 1 && g_base[bl - 1] == '/') {   /* drop trailing slash */
            g_base[--bl] = '\0';
        }
    } else {
        g_base[0] = '\0';
    }
    g_enabled = 1;
}

/* Map a local path to the remote logical path; 1 if under the prefix, else 0. */
BRIXPOSIX_HIDDEN int
map_path(const char *path, char *out, size_t outsz)
{
    const char *rest;

    pthread_once(&g_once, parse_vmp);
    if (!g_enabled || path == NULL || path[0] != '/') {
        return 0;
    }
    if (strncmp(path, g_prefix, g_prefix_len) != 0) {
        return 0;
    }
    rest = path + g_prefix_len;
    if (rest[0] != '\0' && rest[0] != '/') {
        return 0;   /* "/xrddata" must not match prefix "/xrd" */
    }
    if (rest[0] == '\0') {
        rest = "/";
    }
    {
        size_t bl = strlen(g_base);
        size_t rl = strlen(rest);
        if (bl + rl + 1 > outsz) {
            return 0;   /* too long for the remote path buffer: don't divert */
        }
        memcpy(out, g_base, bl);
        memcpy(out + bl, rest, rl + 1);   /* includes the NUL */
    }
    return 1;
}

/* Connect the single session on first use (anonymous; mutex held by caller).
 * §7.7: after a fork() the inherited session is neutered by the library's
 * atfork handler; detect that via brix_conn_usable and transparently open a
 * FRESH child session (already-open shadow fds stay dead — POSIX offers no
 * way to resurrect them safely — but new opens in the child just work). */
BRIXPOSIX_HIDDEN int
ensure_conn(void)
{
    brix_status st;
    if (g_connected) {
        if (brix_conn_usable(&g_conn)) {
            return 0;
        }
        g_connected = 0;   /* forked child: abandon, re-dial below */
    }
    brix_status_clear(&st);
    if (brix_connect(&g_conn, &g_url, NULL, &st) != 0) {
        return -1;
    }
    g_connected = 1;
    return 0;
}

/* shadow fd table (remote read descriptors)                           */


static xfs_slot g_slots[XFS_FD_MAX];

static int
slot_alloc(void)
{
    int i;
    for (i = 0; i < XFS_FD_MAX; i++) {
        if (!g_slots[i].used) {
            memset(&g_slots[i], 0, sizeof(g_slots[i]));
            g_slots[i].used = 1;
            return i;
        }
    }
    return -1;
}

BRIXPOSIX_HIDDEN xfs_slot *
slot_of(int fd)
{
    int i;
    if (fd < XFS_FD_BASE) {
        return NULL;
    }
    i = fd - XFS_FD_BASE;
    if (i < 0 || i >= XFS_FD_MAX || !g_slots[i].used) {
        return NULL;
    }
    return &g_slots[i];
}

BRIXPOSIX_HIDDEN void
fill_stat(const brix_statinfo *si, struct stat *stbuf)
{
    /* One statinfo→stat mapping repo-wide (posix_map.c, shared with both FUSE
     * drivers): the hand-rolled copy this replaced under-filled the result —
     * no st_ino (inode-tracking tools saw everything as one file), no
     * st_blksize/st_blocks, and a guessed 0644/0755 mode instead of the wire
     * flags. allow_symlink=0: the shim stat()s, it never presents S_IFLNK. */
    brix_statinfo_to_stat(si, 0 /* allow_symlink */, stbuf);
}


/* open / openat                                                       */

/* remote_slot_begin — the shared prologue of remote_open / remote_open_write:
 * take g_lock, ensure the shared connection, and allocate a shim slot. On
 * success returns the slot index with g_lock STILL HELD and *s pointing at it;
 * on failure returns -1 with errno set (EIO / EMFILE) and g_lock RELEASED. */
static int
remote_slot_begin(xfs_slot **s)
{
    int slot;

    pthread_mutex_lock(&g_lock);
    if (ensure_conn() != 0) {
        pthread_mutex_unlock(&g_lock);
        errno = EIO;
        return -1;
    }
    slot = slot_alloc();
    if (slot < 0) {
        pthread_mutex_unlock(&g_lock);
        errno = EMFILE;
        return -1;
    }
    *s = &g_slots[slot];
    return slot;
}

static int
remote_open(const char *remote)
{
    int       slot;
    xfs_slot *s;

    slot = remote_slot_begin(&s);
    if (slot < 0) {
        return -1;
    }
    {
        brix_status   st;
        brix_statinfo si;
        brix_status_clear(&st);
        if (brix_rfile_open_read(&g_conn, remote, NULL, 0, -1, &s->f, &st) != 0) {
            s->used = 0;
            pthread_mutex_unlock(&g_lock);
            errno = -brix_kxr_to_errno(&st);
            return -1;
        }
        if (brix_stat(&g_conn, remote, &si, &st) == 0) {
            s->size = si.size;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return XFS_FD_BASE + slot;
}

/* ---- Open a remote file for WRITING (§7.8 preload write path) ----
 *
 * WHAT: Allocates a shim slot backed by a resilient write handle and returns
 *       its shadow fd, or -1/errno. `force` follows the POSIX open flags:
 *       create-new (O_EXCL), overwrite (O_TRUNC/O_CREAT), or update-in-place.
 *
 * WHY:  The shim was read-only; a client `open(O_WRONLY)` under the BRIX_VMP
 *       prefix now streams to the remote instead of hitting the real (absent)
 *       local path. Sequential write + close-commit is the common upload
 *       shape (cp into the mount, a program opening and writing the fd).
 *
 * LIMIT: the shadow fd is a fake number, not a real kernel descriptor, so it
 *        does NOT survive dup2()/fcntl(F_DUPFD) — a shell `> /xrd/out`
 *        redirection (which dup2's the fd onto stdout) will not divert here.
 *        This is symmetric with the read path (`< /xrd/in` has the same
 *        limitation); direct fd use is the supported contract.
 *
 * HOW:  brix_rfile_open_write on the shared connection; the slot is marked
 *       write_mode so read() refuses it and write()/close() route here.
 */
static int
remote_open_write(const char *remote, int force)
{
    int       slot;
    xfs_slot *s;

    slot = remote_slot_begin(&s);
    if (slot < 0) {
        return -1;
    }
    s->write_mode = 1;
    {
        brix_status st;
        brix_status_clear(&st);
        if (brix_rfile_open_write(&g_conn, remote, force, 0 /*posc*/,
                                  0 /*pgrw*/, -1, &s->f, &st) != 0) {
            s->used = 0;
            pthread_mutex_unlock(&g_lock);
            errno = -brix_kxr_to_errno(&st);
            return -1;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return XFS_FD_BASE + slot;
}

/* Map POSIX open flags to the brix write `force` tristate: create-new,
 * overwrite/create, or update-in-place. */
static int
xfs_write_force(int flags)
{
    if ((flags & O_CREAT) && (flags & O_EXCL)) {
        return 0;   /* create-new, fail if exists */
    }
    if ((flags & O_TRUNC) || (flags & O_CREAT)) {
        return 1;   /* overwrite / create */
    }
    return 2;       /* update in place */
}

int
open(const char *path, int flags, ...)
{
    char    remote[XRDC_PATH_MAX];
    mode_t  mode = 0;
    va_list ap;

    REAL(open);
    if ((flags & O_CREAT) != 0) {
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    /* Read → remote read handle; write-only → remote write handle (§7.8).
     * O_RDWR is not divertible (one rfile is read OR write, not both) and
     * falls through to libc. */
    if (map_path(path, remote, sizeof(remote))) {
        if ((flags & O_ACCMODE) == O_RDONLY) {
            return remote_open(remote);
        }
        if ((flags & O_ACCMODE) == O_WRONLY) {
            return remote_open_write(remote, xfs_write_force(flags));
        }
    }
    return real_open(path, flags, mode);
}

int open64(const char *path, int flags, ...) __attribute__((alias("open")));

int
openat(int dirfd, const char *path, int flags, ...)
{
    char    remote[XRDC_PATH_MAX];
    mode_t  mode = 0;
    va_list ap;

    REAL(openat);
    if ((flags & O_CREAT) != 0) {
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (path[0] == '/' && map_path(path, remote, sizeof(remote))) {
        if ((flags & O_ACCMODE) == O_RDONLY) {
            return remote_open(remote);   /* absolute path: dirfd irrelevant */
        }
        if ((flags & O_ACCMODE) == O_WRONLY) {
            return remote_open_write(remote, xfs_write_force(flags));
        }
    }
    return real_openat(dirfd, path, flags, mode);
}

int openat64(int dirfd, const char *path, int flags, ...)
    __attribute__((alias("openat")));

/* read / pread / lseek / close                                        */

ssize_t
read(int fd, void *buf, size_t count)
{
    xfs_slot *s;
    REAL(read);

    s = slot_of(fd);
    if (s == NULL) {
        return real_read(fd, buf, count);
    }
    if (s->write_mode) {   /* §7.8: a write-only shim fd is not readable */
        errno = EBADF;
        return -1;
    }
    {
        brix_status st;
        ssize_t     r;
        pthread_mutex_lock(&g_lock);
        brix_status_clear(&st);
        r = brix_rfile_pread(&s->f, s->pos, buf, count, &st);
        if (r > 0) {
            s->pos += r;
        }
        pthread_mutex_unlock(&g_lock);
        if (r < 0) {
            errno = -brix_kxr_to_errno(&st);
        }
        return r;
    }
}

ssize_t
pread(int fd, void *buf, size_t count, off_t offset)
{
    xfs_slot *s;
    REAL(pread);

    s = slot_of(fd);
    if (s == NULL) {
        return real_pread(fd, buf, count, offset);
    }
    if (s->write_mode) {   /* §7.8: a write-only shim fd is not readable */
        errno = EBADF;
        return -1;
    }
    {
        brix_status st;
        ssize_t     r;
        pthread_mutex_lock(&g_lock);
        brix_status_clear(&st);
        r = brix_rfile_pread(&s->f, (int64_t) offset, buf, count, &st);
        pthread_mutex_unlock(&g_lock);
        if (r < 0) {
            errno = -brix_kxr_to_errno(&st);
        }
        return r;
    }
}

ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
    __attribute__((alias("pread")));

/* write / pwrite (§7.8): stream into the remote write handle at the slot's
 * current (or explicit) offset. Non-shim fds and read-only shim slots pass
 * through / error exactly as the kernel would. */
ssize_t
write(int fd, const void *buf, size_t count)
{
    xfs_slot *s;
    REAL(write);

    s = slot_of(fd);
    if (s == NULL) {
        return real_write(fd, buf, count);
    }
    if (!s->write_mode) {   /* a read-only shim fd is not writable */
        errno = EBADF;
        return -1;
    }
    {
        brix_status st;
        int         rc;
        pthread_mutex_lock(&g_lock);
        brix_status_clear(&st);
        rc = brix_rfile_pwrite(&s->f, s->pos, buf, count, &st);
        if (rc == 0) {
            s->pos += (int64_t) count;
        }
        pthread_mutex_unlock(&g_lock);
        if (rc != 0) {
            errno = -brix_kxr_to_errno(&st);
            return -1;
        }
        return (ssize_t) count;
    }
}

ssize_t
pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    xfs_slot *s;
    REAL(pwrite);

    s = slot_of(fd);
    if (s == NULL) {
        return real_pwrite(fd, buf, count, offset);
    }
    if (!s->write_mode) {
        errno = EBADF;
        return -1;
    }
    {
        brix_status st;
        int         rc;
        pthread_mutex_lock(&g_lock);
        brix_status_clear(&st);
        rc = brix_rfile_pwrite(&s->f, (int64_t) offset, buf, count, &st);
        pthread_mutex_unlock(&g_lock);
        if (rc != 0) {
            errno = -brix_kxr_to_errno(&st);
            return -1;
        }
        return (ssize_t) count;
    }
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset)
    __attribute__((alias("pwrite")));

off_t
lseek(int fd, off_t offset, int whence)
{
    xfs_slot *s;
    REAL(lseek);

    s = slot_of(fd);
    if (s == NULL) {
        return real_lseek(fd, offset, whence);
    }
    switch (whence) {
    case SEEK_SET: s->pos = offset; break;
    case SEEK_CUR: s->pos += offset; break;
    case SEEK_END: s->pos = s->size + offset; break;
    default:       errno = EINVAL; return (off_t) -1;
    }
    return (off_t) s->pos;
}

off_t lseek64(int fd, off_t offset, int whence) __attribute__((alias("lseek")));

int
close(int fd)
{
    xfs_slot *s;
    REAL(close);

    s = slot_of(fd);
    if (s == NULL) {
        return real_close(fd);
    }
    {
        brix_status st;
        pthread_mutex_lock(&g_lock);
        brix_status_clear(&st);
        (void) brix_rfile_close(&s->f, &st);
        s->used = 0;
        pthread_mutex_unlock(&g_lock);
    }
    return 0;
}

/*
 * Directory enumeration (opendir/readdir/closedir) over the prefix is a
 * documented follow-up: the opaque DIR* plus glibc's readdir/readdir64 +
 * dirfd()/fstatat() interplay can't be interposed safely without risking
 * unrelated programs. Use `xrdfs ls` or the FUSE mount (xrootdfs) to enumerate;
 * the preload covers the file READ path (open/read/pread/lseek/stat/access).
 */
