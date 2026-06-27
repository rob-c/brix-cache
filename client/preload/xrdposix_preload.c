/*
 * xrdposix_preload.c — an LD_PRELOAD shim that routes POSIX reads of a configured
 * path prefix to an XRootD root:// export via libxrdc.
 *
 * WHAT: Interpose open/read/pread/lseek/close, the stat family (incl. statx and
 *       the LFS *64 variants) and access on libc. Any
 *       path under the prefix named by $XROOTD_VMP is served from a remote XRootD
 *       server; every other path passes straight through to the real libc call.
 * WHY:  Legacy tools that only know POSIX paths (cat, md5sum, ls, analysis jobs)
 *       can read remote XRootD data with no recompile and NO libXrdCl/XrdPosix --
 *       just LD_PRELOAD=libxrdposix_preload.so XROOTD_VMP=/xrd=root://host:port/.
 * HOW:  $XROOTD_VMP = "<localprefix>=root://host[:port][/base]". A path that
 *       starts with <localprefix> is rewritten to the remote logical path and
 *       opened through a single lazily-connected libxrdc session (one request in
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
 * Clean-room: composes the public libxrdc API + dlsym only; no XrdPosix code.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* RTLD_NEXT, *64 variants (the build also passes -D_GNU_SOURCE) */
#endif
#include "xrdc.h"

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

/* configuration (XROOTD_VMP) + the lazily-connected session           */

static pthread_once_t  g_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int       g_enabled;            /* XROOTD_VMP parsed and usable */
static char      g_prefix[256];        /* local path prefix, e.g. "/xrd" */
static size_t    g_prefix_len;
static xrdc_url  g_url;                 /* remote endpoint + base path */
static char      g_base[XRDC_PATH_MAX]; /* remote base ("" when "/") */

static xrdc_conn g_conn;
static int       g_connected;

static void
parse_vmp(void)
{
    const char *vmp = getenv("XROOTD_VMP");
    const char *eq;
    char        url[512];
    xrdc_status st;

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
    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(url, &g_url, &st) != 0) {
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
static int
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

/* Connect the single session on first use (anonymous; mutex held by caller). */
static int
ensure_conn(void)
{
    xrdc_status st;
    if (g_connected) {
        return 0;
    }
    xrdc_status_clear(&st);
    if (xrdc_connect(&g_conn, &g_url, NULL, &st) != 0) {
        return -1;
    }
    g_connected = 1;
    return 0;
}

/* shadow fd table (remote read descriptors)                           */

#define XFS_FD_BASE 0x40000000
#define XFS_FD_MAX  1024

typedef struct {
    int        used;
    xrdc_rfile f;     /* resilient: reopens + resumes after a sever */
    int64_t    pos;
    int64_t    size;
} xfs_slot;

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

static xfs_slot *
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

static void
fill_stat(const xrdc_statinfo *si, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(*stbuf));
    if (si->flags & kXR_isDir) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = (off_t) si->size;
    }
    stbuf->st_mtime = stbuf->st_atime = stbuf->st_ctime = (time_t) si->mtime;
}

/* Resolve (once) the real libc symbol behind the wrapper we're standing in. The
 * variable inherits libc's exact prototype via __typeof__(name). */
#define REAL(name)                                                      \
    static __typeof__(name) *real_##name = NULL;                        \
    if (real_##name == NULL) {                                          \
        real_##name = (__typeof__(name) *) dlsym(RTLD_NEXT, #name);     \
    }

/* open / openat                                                       */

static int
remote_open(const char *remote)
{
    int       slot;
    xfs_slot *s;

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
    s = &g_slots[slot];
    {
        xrdc_status   st;
        xrdc_statinfo si;
        xrdc_status_clear(&st);
        if (xrdc_rfile_open_read(&g_conn, remote, NULL, 0, -1, &s->f, &st) != 0) {
            s->used = 0;
            pthread_mutex_unlock(&g_lock);
            errno = -xrdc_kxr_to_errno(&st);
            return -1;
        }
        if (xrdc_stat(&g_conn, remote, &si, &st) == 0) {
            s->size = si.size;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return XFS_FD_BASE + slot;
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
    /* Only the read path is diverted; writes/creates fall through to libc. */
    if ((flags & O_ACCMODE) == O_RDONLY && map_path(path, remote, sizeof(remote))) {
        return remote_open(remote);
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
    if ((flags & O_ACCMODE) == O_RDONLY && path[0] == '/' &&
        map_path(path, remote, sizeof(remote))) {
        return remote_open(remote);   /* absolute path: dirfd irrelevant */
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
    {
        xrdc_status st;
        ssize_t     r;
        pthread_mutex_lock(&g_lock);
        xrdc_status_clear(&st);
        r = xrdc_rfile_pread(&s->f, s->pos, buf, count, &st);
        if (r > 0) {
            s->pos += r;
        }
        pthread_mutex_unlock(&g_lock);
        if (r < 0) {
            errno = -xrdc_kxr_to_errno(&st);
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
    {
        xrdc_status st;
        ssize_t     r;
        pthread_mutex_lock(&g_lock);
        xrdc_status_clear(&st);
        r = xrdc_rfile_pread(&s->f, (int64_t) offset, buf, count, &st);
        pthread_mutex_unlock(&g_lock);
        if (r < 0) {
            errno = -xrdc_kxr_to_errno(&st);
        }
        return r;
    }
}

ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
    __attribute__((alias("pread")));

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
        xrdc_status st;
        pthread_mutex_lock(&g_lock);
        xrdc_status_clear(&st);
        (void) xrdc_rfile_close(&s->f, &st);
        s->used = 0;
        pthread_mutex_unlock(&g_lock);
    }
    return 0;
}

/* stat family + access                                                */

static int
remote_stat(const char *remote, struct stat *stbuf)
{
    xrdc_status   st;
    xrdc_statinfo si;
    int           rc;

    pthread_mutex_lock(&g_lock);
    if (ensure_conn() != 0) {
        pthread_mutex_unlock(&g_lock);
        errno = EIO;
        return -1;
    }
    xrdc_status_clear(&st);
    rc = xrdc_stat(&g_conn, remote, &si, &st);
    pthread_mutex_unlock(&g_lock);
    if (rc != 0) {
        errno = -xrdc_kxr_to_errno(&st);
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
    xrdc_status   st;
    xrdc_statinfo si;
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
    xrdc_status_clear(&st);
    rc = xrdc_stat(&g_conn, remote, &si, &st);
    pthread_mutex_unlock(&g_lock);
    if (rc != 0) {
        errno = -xrdc_kxr_to_errno(&st);
        return -1;
    }
    memset(stxbuf, 0, sizeof(*stxbuf));
    stxbuf->stx_mask = STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_SIZE
                       | STATX_MTIME;
    stxbuf->stx_blksize = 4096;
    if (si.flags & kXR_isDir) {
        stxbuf->stx_mode = S_IFDIR | 0755;
        stxbuf->stx_nlink = 2;
    } else {
        stxbuf->stx_mode = S_IFREG | 0644;
        stxbuf->stx_nlink = 1;
        stxbuf->stx_size = (uint64_t) si.size;
        stxbuf->stx_blocks = (uint64_t) ((si.size + 511) / 512);
    }
    stxbuf->stx_mtime.tv_sec = si.mtime;
    stxbuf->stx_atime.tv_sec = si.mtime;
    stxbuf->stx_ctime.tv_sec = si.mtime;
    return 0;
}

/*
 * Directory enumeration (opendir/readdir/closedir) over the prefix is a
 * documented follow-up: the opaque DIR* plus glibc's readdir/readdir64 +
 * dirfd()/fstatat() interplay can't be interposed safely without risking
 * unrelated programs. Use `xrdfs ls` or the FUSE mount (xrootdfs) to enumerate;
 * the preload covers the file READ path (open/read/pread/lseek/stat/access).
 */
