/*
 * brixposix_dir.c — §7.8 readdir family for the POSIX preload shim.
 *
 * WHAT: opendir/readdir/closedir (+ rewinddir/telldir/seekdir/dirfd/
 *       readdir_r; the glibc *64 spellings forward here from
 *       lib/platform/linux/preload_lfs.c) for paths under the BRIX_VMP
 *       prefix, so `ls`, `find` and anything else that walks a directory
 *       sees the remote namespace instead of ENOENT.
 * WHY:  The shim could open and read a remote FILE but could not LIST one,
 *       which meant every tool that discovers its inputs — as opposed to
 *       being handed them — fell straight through to a local path that does
 *       not exist.  Read-only access you cannot enumerate is barely access.
 * HOW:  One kXR_dirlist at opendir time, materialised into a snapshot the
 *       handle owns; readdir walks the snapshot.  The DIR* we hand back is
 *       our own object, so every wrapper first asks the registry "is this
 *       one of mine?" by POINTER IDENTITY and passes anything else to the
 *       real libc function untouched — a foreign DIR* is never dereferenced
 *       by this code.
 *
 * Deliberately narrow, symmetric with the rest of the shim: scandir(),
 * glob() and ftw() are not interposed (they are libc code paths that call
 * opendir/readdir, so they work through THESE wrappers when the entry point
 * is the one we replaced, and not otherwise).
 */
#include "brixposix_internal.h"
#include "brix_ops.h"

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define XFS_DIR_MAX 128

typedef struct {
    brix_dirent      *ents;    /* snapshot, malloc'd by brix_dirlist */
    size_t            count;
    size_t            pos;     /* 0 = ".", 1 = "..", 2+ = ents[pos - 2] */
    struct dirent     de;
} xfs_dir;

static pthread_mutex_t g_dir_lock = PTHREAD_MUTEX_INITIALIZER;
static xfs_dir        *g_dirs[XFS_DIR_MAX];

/* ---- registry ----------------------------------------------------------
 * A DIR* is ours only if this table holds it.  Pointer identity is the only
 * safe test: a magic field would mean dereferencing libc's DIR, whose layout
 * is opaque and whose memory we do not own.
 */
static int
dir_register(xfs_dir *d)
{
    int i;

    pthread_mutex_lock(&g_dir_lock);
    for (i = 0; i < XFS_DIR_MAX; i++) {
        if (g_dirs[i] == NULL) {
            g_dirs[i] = d;
            pthread_mutex_unlock(&g_dir_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_dir_lock);
    return -1;
}

static xfs_dir *
dir_of(DIR *dirp)
{
    int i;
    xfs_dir *found = NULL;

    if (dirp == NULL) {
        return NULL;
    }
    pthread_mutex_lock(&g_dir_lock);
    for (i = 0; i < XFS_DIR_MAX; i++) {
        if (g_dirs[i] == (xfs_dir *) dirp) {
            found = g_dirs[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_dir_lock);
    return found;
}

static void
dir_unregister(const xfs_dir *d)
{
    int i;

    pthread_mutex_lock(&g_dir_lock);
    for (i = 0; i < XFS_DIR_MAX; i++) {
        if (g_dirs[i] == d) {
            g_dirs[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_dir_lock);
}

/* ---- entry synthesis ---------------------------------------------------
 * d_ino must be NON-ZERO: a zero inode means "deleted" to readdir consumers
 * (glibc's own readdir_r documentation, and every tool that copies that
 * convention), so an entry carrying one is skipped by code that has nothing
 * to do with us.  The server's file id is used when it sent one, and a
 * name-derived FNV-1a fills in when it did not.
 */
static uint64_t
dir_ino(const brix_dirent *e)
{
    uint64_t h = 1469598103934665603ULL;
    const unsigned char *p;

    if (e->have_stat && e->st.id != 0) {
        return (uint64_t) e->st.id;
    }
    for (p = (const unsigned char *) e->name; *p != '\0'; p++) {
        h = (h ^ *p) * 1099511628211ULL;
    }
    return h | 1ULL;   /* never 0, whatever the hash lands on */
}

/* DT_DIR/DT_REG when the listing carried a stat, DT_UNKNOWN otherwise —
 * which is a legal answer that sends the caller to stat(), and the shim
 * interposes that too. */
static unsigned char
dir_type(const brix_dirent *e)
{
    struct stat sb;

    if (!e->have_stat) {
        return DT_UNKNOWN;
    }
    fill_stat(&e->st, &sb);
    if (S_ISDIR(sb.st_mode)) {
        return DT_DIR;
    }
    if (S_ISLNK(sb.st_mode)) {
        return DT_LNK;
    }
    if (S_ISREG(sb.st_mode)) {
        return DT_REG;
    }
    return DT_UNKNOWN;
}

/* Fill one entry from the snapshot position, or return 0 at end-of-stream.
 * Positions 0 and 1 are "." and "..": the wire listing does not carry them,
 * and a directory without them is not a POSIX directory — `find` prunes on
 * their absence and `rm -r` has been known to loop. */
static int
dir_fill(xfs_dir *d, uint64_t *ino, unsigned char *type, const char **name)
{
    const brix_dirent *e;

    if (d->pos == 0) {
        *ino = 1; *type = DT_DIR; *name = ".";
        return 1;
    }
    if (d->pos == 1) {
        *ino = 2; *type = DT_DIR; *name = "..";
        return 1;
    }
    if (d->pos - 2 >= d->count) {
        return 0;
    }
    e = &d->ents[d->pos - 2];
    *ino = dir_ino(e); *type = dir_type(e); *name = e->name;
    return 1;
}

static int
dir_next(xfs_dir *d, struct dirent *out)
{
    uint64_t ino;
    unsigned char type;
    const char *name;
    size_t len;

    if (!dir_fill(d, &ino, &type, &name)) {
        return 0;
    }
    memset(out, 0, sizeof(*out));
    out->d_ino = (ino_t) ino;
    out->d_reclen = (unsigned short) sizeof(*out);
    out->d_type = type;
    len = strlen(name);
    if (len >= sizeof(out->d_name)) {
        d->pos++;
        return dir_next(d, out);   /* unrepresentable name: skip, never crop */
    }
    memcpy(out->d_name, name, len + 1);
    /* the host's own cursor / length fields (d_off; d_seekoff + d_namlen) */
    BRIXPOSIX_DIRENT_FINISH(out, d->pos + 1, len);
    d->pos++;
    return 1;
}

/* ---- interposed entry points ------------------------------------------ */

/* One listing into a freshly allocated handle.  Returns 0, or -1 with errno
 * already carrying the server's own answer: a listing refused for want of
 * authorization must not reach the caller as ENOENT, which would read as
 * "empty directory, nothing to see" and hide the refusal. */
static int
dir_fetch(const char *remote, xfs_dir *d)
{
    brix_status st;
    int rc;

    pthread_mutex_lock(&g_lock);
    if (ensure_conn() != 0) {
        pthread_mutex_unlock(&g_lock);
        errno = EIO;
        return -1;
    }
    brix_status_clear(&st);
    rc = brix_dirlist(&g_conn, remote, 1, &d->ents, &d->count, &st);
    pthread_mutex_unlock(&g_lock);
    if (rc != 0) {
        errno = -brix_kxr_to_errno(&st);
        return -1;
    }
    return 0;
}

DIR *
BRIXPOSIX_WRAP(opendir)(const char *name)
{
    char remote[XRDC_PATH_MAX];
    xfs_dir *d;

    REAL(opendir);
    if (!map_path(name, remote, sizeof(remote))) {
        return real_opendir(name);   /* map_path is the NULL gate too */
    }
    d = calloc(1, sizeof(*d));
    if (d == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    if (dir_fetch(remote, d) != 0) {
        free(d);
        return NULL;
    }
    if (dir_register(d) != 0) {
        free(d->ents);
        free(d);
        errno = EMFILE;
        return NULL;
    }
    return (DIR *) d;
}

struct dirent *
BRIXPOSIX_WRAP(readdir)(DIR *dirp)
{
    xfs_dir *d = dir_of(dirp);

    REAL(readdir);
    if (d == NULL) {
        return real_readdir(dirp);
    }
    if (!dir_next(d, &d->de)) {
        return NULL;        /* end of directory: NULL with errno untouched */
    }
    return &d->de;
}

/* glibc deprecates readdir_r for its callers.  We are not a caller: we are
 * standing in for it, and a threaded program that still uses it must not
 * quietly get libc's local-filesystem answer for a remote path. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
int
BRIXPOSIX_WRAP(readdir_r)(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    xfs_dir *d = dir_of(dirp);

    REAL(readdir_r);
    if (d == NULL) {
        return real_readdir_r(dirp, entry, result);
    }
    *result = dir_next(d, entry) ? entry : NULL;
    return 0;
}
#pragma GCC diagnostic pop

int
BRIXPOSIX_WRAP(closedir)(DIR *dirp)
{
    xfs_dir *d = dir_of(dirp);

    REAL(closedir);
    if (d == NULL) {
        return real_closedir(dirp);
    }
    dir_unregister(d);
    free(d->ents);
    free(d);
    return 0;
}

void
BRIXPOSIX_WRAP(rewinddir)(DIR *dirp)
{
    xfs_dir *d = dir_of(dirp);

    REAL(rewinddir);
    if (d == NULL) {
        real_rewinddir(dirp);
        return;
    }
    d->pos = 0;   /* the SNAPSHOT is not refetched: see the file header */
}

long
BRIXPOSIX_WRAP(telldir)(DIR *dirp)
{
    xfs_dir *d = dir_of(dirp);

    REAL(telldir);
    if (d == NULL) {
        return real_telldir(dirp);
    }
    return (long) d->pos;
}

void
BRIXPOSIX_WRAP(seekdir)(DIR *dirp, long loc)
{
    xfs_dir *d = dir_of(dirp);

    REAL(seekdir);
    if (d == NULL) {
        real_seekdir(dirp, loc);
        return;
    }
    if (loc >= 0) {
        d->pos = (size_t) loc;   /* telldir cookies are our own positions */
    }
}

/* There is no file descriptor behind a remote listing, and inventing one
 * would be worse than refusing: a caller that took it would openat() into
 * the wrong directory — or, with a shadow fd number, into nothing at all. */
int
BRIXPOSIX_WRAP(dirfd)(DIR *dirp)
{
    xfs_dir *d = dir_of(dirp);

    REAL(dirfd);
    if (d == NULL) {
        return real_dirfd(dirp);
    }
    errno = ENOTSUP;
    return -1;
}
