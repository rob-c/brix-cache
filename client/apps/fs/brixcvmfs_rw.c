/*
 * brixcvmfs_rw.c — the cvmfs-rw union driver: full POSIX write semantics on
 * top of the read-only CVMFS-brix mount.
 *
 * WHAT: a FUSE ops table that unions a local writable upper tree
 *       (<mnt>/.brixwrites/upper, sibling of .brixcache, reached via a dirfd
 *       preserved from before the mount) over the CVMFS lower layer: create/
 *       write/truncate/mkdir/rename land in upper (copy-up on first write),
 *       deletes leave whiteout markers, and /.brixwrites itself is exposed as
 *       a read-write passthrough subtree so --overlay-list/--overlay-reset
 *       work on the live mount.
 * WHY:  jobs need scratch/patch space "inside" the software repo without ever
 *       touching upstream; the upper tree is a plain path-mirroring dir —
 *       inspectable, diffable, rm -rf-resettable.
 * HOW:  every op consults the overlay core (client/lib/fs/overlay.h) first
 *       and falls back to the brixcvmfs_op_* read-only ops for lower cases;
 *       upper always wins. Single-threaded (-s) like the ro driver, so no
 *       locking. Op handlers return 0/-errno.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "brixcvmfs_internal.h"
#include "fs/overlay.h"
#include "brixcvmfs_rw_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

/* ---- process-global overlay state (one mount per process, like g_cl) ----- */

brix_overlay g_ov;
int          g_writes_fd = -1;

/* ---- small path/layer helpers ------------------------------------------- */

/* FUSE path → overlay-relative ("" = root) */
const char *ov_rel(const char *path) {
    return path[0] == '/' ? path + 1 : path;
}

/* FUSE path → .brixwrites-relative when inside the passthrough subtree
 * ("" = the subtree root), else NULL. */
const char *pt_rel(const char *path) {
    static const size_t n = sizeof(BRIX_OV_DIRNAME) - 1;
    if (strncmp(path + 1, BRIX_OV_DIRNAME, n) != 0) return NULL;
    const char *rest = path + 1 + n;
    if (rest[0] == '\0') return "";
    if (rest[0] == '/')  return rest + 1;
    return NULL;
}

/* "" → "." for *at() calls on the subtree root */
const char *pt_at(const char *pr) { return pr[0] ? pr : "."; }

/* leaf component of a FUSE path */
static const char *path_leaf(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* overlay vocabulary (and the cache root) may never be created/touched */
int rw_reserved(const char *path) {
    if (brix_ov_name_reserved(path_leaf(path))) return 1;
    if (strcmp(path, "/.brixcache") == 0) return 1;
    return 0;
}

/* lower-layer resolve: 1 found / 0 absent / -1 error */
int lower_resolve(const char *path, cvmfs_dirent_t *e) {
    return cvmfs_client_resolve(brixcvmfs_client(), brixcvmfs_cat_path(path),
                                e, brixcvmfs_mono_now());
}

int lower_is_dir(const cvmfs_dirent_t *e)  { return (e->flags & CVMFS_FLAG_DIR)  != 0; }
int lower_is_file(const cvmfs_dirent_t *e) { return (e->flags & CVMFS_FLAG_FILE) != 0; }

/* classify shorthand */
int rw_classify(const char *path, struct stat *st, brix_ov_state *s) {
    return brix_overlay_classify(&g_ov, ov_rel(path), st, s);
}

/* does the union view show anything at `path`? */
int merged_exists(const char *path) {
    struct stat   st;
    brix_ov_state s;
    if (rw_classify(path, &st, &s) != 0) return 0;
    if (s == BRIX_OV_UPPER)  return 1;
    if (s == BRIX_OV_MASKED) return 0;
    cvmfs_dirent_t e;
    return lower_resolve(path, &e) == 1;
}

/* ---- union locate (shared upper/lower/whiteout resolution) --------------- */


/*
 * WHAT: classify `path` in upper, then resolve lower unless masked.
 * WHY:  mutation ops (unlink, rename source) need the lower dirent even when
 *       upper wins (to decide whether a whiteout is required), but a masked
 *       path returns -ENOENT before the catalog is ever consulted.
 * HOW:  masked short-circuits with lower = 0; catalog errors map to -EIO.
 */
int ov_locate(const char *path, ov_loc_t *l) {
    int rc = rw_classify(path, &l->st, &l->s);
    if (rc != 0) return rc;
    l->lower = 0;
    if (l->s == BRIX_OV_MASKED) return 0;
    l->lower = lower_resolve(path, &l->e);
    return l->lower < 0 ? -EIO : 0;
}

/*
 * WHAT: like ov_locate, but the catalog is consulted only when upper has no
 *       say at all (state NONE).
 * WHY:  open and rename-target only care about the merged VIEW — an upper hit
 *       or whiteout already decides the outcome, so lower must stay unresolved
 *       there (a masked path must look absent, never like a lower hit).
 * HOW:  upper/masked leave lower = 0; catalog errors map to -EIO.
 */
int ov_locate_visible(const char *path, ov_loc_t *l) {
    int rc = rw_classify(path, &l->st, &l->s);
    if (rc != 0) return rc;
    l->lower = l->s == BRIX_OV_NONE ? lower_resolve(path, &l->e) : 0;
    return l->lower < 0 ? -EIO : 0;
}

/* ---- copy-up plumbing ---------------------------------------------------- */

/* overlay read seam → cvmfs_client_read (rel carries no leading slash) */
static int rw_read_lower(void *ud, const char *rel, uint64_t off, size_t len,
                         unsigned char *buf, size_t *outlen) {
    (void) ud;
    char path[1024];
    snprintf(path, sizeof(path), "/%s", rel);
    int rc = cvmfs_client_read(brixcvmfs_client(), path, off, len, buf, outlen,
                               brixcvmfs_mono_now());
    return rc == 0 ? 0 : -EIO;
}

/* upper dirs created during copy-up/mkdir mirror the lower dir modes */
mode_t rw_lower_dir_mode(void *ud, const char *rel_dir) {
    (void) ud;
    char path[1024];
    snprintf(path, sizeof(path), "/%s", rel_dir);
    cvmfs_dirent_t e;
    if (lower_resolve(path, &e) == 1 && lower_is_dir(&e))
        return e.mode & 07777;
    return 0755;
}

/* ensure the upper parent chain of `path` exists (lower-mirrored modes) */
int rw_ensure_parents(const char *path) {
    const char *rel   = ov_rel(path);
    const char *slash = strrchr(rel, '/');
    if (slash == NULL) return 0;                 /* parent is the root */
    char parent[1024];
    size_t n = (size_t) (slash - rel);
    if (n >= sizeof(parent)) return -ENAMETOOLONG;
    memcpy(parent, rel, n);
    parent[n] = '\0';
    return brix_overlay_mkdirs(&g_ov, parent, rw_lower_dir_mode, NULL);
}

/* materialise lower file `path` (dirent e) in the upper tree */
int rw_copyup(const char *path, const cvmfs_dirent_t *e) {
    int rc = rw_ensure_parents(path);
    if (rc != 0) return rc;
    struct stat lst = { 0 };
    lst.st_size  = (off_t) e->size;
    lst.st_mode  = S_IFREG | (e->mode & 07777);
    lst.st_mtime = (time_t) e->mtime;
    return brix_overlay_copyup(&g_ov, ov_rel(path), &lst, rw_read_lower, NULL);
}

/* ---- open/create/read/write --------------------------------------------- */

/* fi->fh: 0 = lower-served (read-only), else upper/passthrough fd + 1 */
static int fh_store(struct fuse_file_info *fi, int fd) {
    fi->fh = (uint64_t) fd + 1;
    return 0;
}

/* does this open intend to modify the file's bytes? */
static int rw_want_write(int oflags) {
    return (oflags & O_ACCMODE) != O_RDONLY || (oflags & O_TRUNC);
}

/*
 * WHAT: open a path the upper layer already owns.
 * WHY:  upper always wins — no lower consult, but O_CREAT|O_EXCL must still
 *       see the existing entry and directories can't be opened for data.
 * HOW:  strips O_CREAT (the file exists) and opens straight in upper.
 */
static int rw_open_upper(const char *path, const struct stat *st, int oflags,
                         mode_t mode, struct fuse_file_info *fi) {
    if (S_ISDIR(st->st_mode)) return -EISDIR;
    if ((oflags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) return -EEXIST;
    int fd = brix_overlay_open(&g_ov, ov_rel(path), oflags & ~O_CREAT, mode);
    return fd < 0 ? fd : fh_store(fi, fd);
}

/*
 * WHAT: open a path visible in neither layer (masked or truly absent).
 * WHY:  only O_CREAT may conjure it; a fresh upper file over a whiteout must
 *       clear the whiteout or the new file would stay invisible.
 * HOW:  mirror the parent chain into upper, create, clear the whiteout.
 */
static int rw_open_create(const char *path, int oflags, mode_t mode,
                          struct fuse_file_info *fi) {
    if (!(oflags & O_CREAT)) return -ENOENT;
    int rc = rw_ensure_parents(path);
    if (rc != 0) return rc;
    int fd = brix_overlay_open(&g_ov, ov_rel(path), oflags, mode);
    if (fd < 0) return fd;
    brix_overlay_whiteout_clear(&g_ov, ov_rel(path));
    return fh_store(fi, fd);
}

/*
 * WHAT: open a path that only the lower layer has (dirent `e`).
 * WHY:  reads stay lower-served (fh = 0 → ro driver); the first write
 *       triggers copy-up so upper owns the bytes from then on.
 * HOW:  refuse dirs/symlinks for writing, copy-up, then open in upper with
 *       O_CREAT|O_EXCL stripped (copy-up just created the upper file).
 */
static int rw_open_lower(const char *path, const cvmfs_dirent_t *e, int oflags,
                         mode_t mode, struct fuse_file_info *fi) {
    if (lower_is_dir(e)) return -EISDIR;
    if (!rw_want_write(oflags)) { fi->fh = 0; return brixcvmfs_op_open(path, fi); }
    if (!lower_is_file(e)) return -EPERM;        /* symlink write-through: no */
    if (oflags & O_EXCL) return -EEXIST;

    int rc = rw_copyup(path, e);                 /* first write → copy-up */
    if (rc != 0) return rc;
    int fd = brix_overlay_open(&g_ov, ov_rel(path), oflags & ~(O_CREAT | O_EXCL), mode);
    return fd < 0 ? fd : fh_store(fi, fd);
}

/*
 * WHAT: the shared open/create/mknod entry — route to the owning layer.
 * WHY:  every open variant needs the same passthrough/reserved gating and the
 *       same union resolution before the per-layer semantics diverge.
 * HOW:  passthrough subtree → direct openat; else locate in the merged view
 *       and dispatch to the upper / create / lower helper.
 */
static int rw_open_common(const char *path, int oflags, mode_t mode,
                          struct fuse_file_info *fi) {
    const char *pr = pt_rel(path);
    if (pr != NULL) {
        int fd = openat(g_writes_fd, pt_at(pr), oflags | O_NOFOLLOW, mode);
        return fd < 0 ? -errno : fh_store(fi, fd);
    }
    if (rw_reserved(path))
        return rw_want_write(oflags) || (oflags & O_CREAT) ? -EPERM : -ENOENT;

    ov_loc_t l;
    int rc = ov_locate_visible(path, &l);
    if (rc != 0) return rc;
    if (l.s == BRIX_OV_UPPER) return rw_open_upper(path, &l.st, oflags, mode, fi);
    if (l.lower == 0)         return rw_open_create(path, oflags, mode, fi);
    return rw_open_lower(path, &l.e, oflags, mode, fi);
}

int rw_open(const char *path, struct fuse_file_info *fi) {
    return rw_open_common(path, fi->flags, 0644, fi);
}

int rw_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    return rw_open_common(path, fi->flags | O_CREAT, mode, fi);
}

int rw_mknod(const char *path, mode_t mode, dev_t dev) {
    (void) dev;
    if (!S_ISREG(mode)) return -EPERM;
    struct fuse_file_info fi = { 0 };
    fi.flags = O_WRONLY | O_CREAT | O_EXCL;
    int rc = rw_open_common(path, fi.flags, mode, &fi);
    if (rc == 0 && fi.fh) close((int) fi.fh - 1);
    return rc;
}

int rw_read(const char *path, char *buf, size_t size, off_t off,
                   struct fuse_file_info *fi) {
    if (fi != NULL && fi->fh != 0) {
        ssize_t n = pread((int) fi->fh - 1, buf, size, off); /* vfs-seam-allow: FUSE rw_read on local writable CVMFS overlay fd, not export VFS object */
        return n < 0 ? -errno : (int) n;
    }
    return brixcvmfs_op_read(path, buf, size, off, fi);
}

int rw_write(const char *path, const char *buf, size_t size, off_t off,
                    struct fuse_file_info *fi) {
    (void) path;
    if (fi == NULL || fi->fh == 0) return -EBADF;
    ssize_t n = pwrite((int) fi->fh - 1, buf, size, off); /* vfs-seam-allow: FUSE rw_write on local writable CVMFS overlay fd, not export VFS object */
    return n < 0 ? -errno : (int) n;
}

int rw_release(const char *path, struct fuse_file_info *fi) {
    (void) path;
    if (fi != NULL && fi->fh != 0) close((int) fi->fh - 1);
    return 0;
}

int rw_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    (void) path;
    if (fi == NULL || fi->fh == 0) return 0;
    int fd = (int) fi->fh - 1;
    return (datasync ? fdatasync(fd) : fsync(fd)) != 0 ? -errno : 0;
}

int rw_truncate(const char *path, off_t len, struct fuse_file_info *fi) {
    if (fi != NULL && fi->fh != 0)
        return ftruncate((int) fi->fh - 1, len) != 0 ? -errno : 0;

    const char *pr = pt_rel(path);
    if (pr != NULL) {
        int fd = openat(g_writes_fd, pt_at(pr), O_WRONLY | O_NOFOLLOW);
        if (fd < 0) return -errno;
        int rc = ftruncate(fd, len) != 0 ? -errno : 0;
        close(fd);
        return rc;
    }
    if (rw_reserved(path)) return -EPERM;

    struct stat   st;
    brix_ov_state s;
    int rc = rw_classify(path, &st, &s);
    if (rc != 0) return rc;
    if (s == BRIX_OV_UPPER) return brix_overlay_truncate(&g_ov, ov_rel(path), len);
    if (s == BRIX_OV_MASKED) return -ENOENT;

    cvmfs_dirent_t e;
    int lower = lower_resolve(path, &e);
    if (lower < 0) return -EIO;
    if (lower == 0) return -ENOENT;
    if (lower_is_dir(&e)) return -EISDIR;
    rc = rw_copyup(path, &e);
    return rc != 0 ? rc : brix_overlay_truncate(&g_ov, ov_rel(path), len);
}

/* ---- getattr / readdir --------------------------------------------------- */

int rw_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    const char *pr = pt_rel(path);
    if (pr != NULL)
        return fstatat(g_writes_fd, pt_at(pr), st, AT_SYMLINK_NOFOLLOW) != 0 ? -errno : 0;
    if (strcmp(path, "/") == 0) return brixcvmfs_op_getattr(path, st, fi);

    brix_ov_state s;
    int rc = rw_classify(path, st, &s);
    if (rc != 0) return rc;
    if (s == BRIX_OV_UPPER)  return 0;
    if (s == BRIX_OV_MASKED) return -ENOENT;
    return brixcvmfs_op_getattr(path, st, fi);
}

static int pt_readdir(const char *pr, void *buf, fuse_fill_dir_t filler) {
    int fd = openat(g_writes_fd, pt_at(pr), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -errno;
    DIR *d = fdopendir(fd);                      /* owns fd */
    if (d == NULL) { int e = errno; close(fd); return -e; }
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            filler(buf, e->d_name, NULL, 0, 0);
    closedir(d);
    return 0;
}

typedef struct {
    void                  *buf;
    fuse_fill_dir_t        filler;
    const brix_ov_nameset *set;
} rw_lowdir_t;

/* lower pass: emit names neither shadowed ('u') nor whiteouted ('w') */
static void rw_lowdir_emit(const cvmfs_dirent_t *e, void *ud) {
    rw_lowdir_t *c = ud;
    if (e->name[0] == '\0') return;
    if (brix_ov_nameset_flag(c->set, e->name) != 0) return;
    c->filler(c->buf, e->name, NULL, 0, 0);
}

int rw_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags fl) {
    (void) off; (void) fi; (void) fl;
    const char *pr = pt_rel(path);
    if (pr != NULL) return pt_readdir(pr, buf, filler);

    cvmfs_client_refresh(brixcvmfs_client(), brixcvmfs_mono_now());

    struct stat   st;
    brix_ov_state s;
    int rc = rw_classify(path, &st, &s);
    if (rc != 0) return rc;
    if (s == BRIX_OV_MASKED) return -ENOENT;
    if (s == BRIX_OV_UPPER && !S_ISDIR(st.st_mode)) return -ENOTDIR;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    if (strcmp(path, "/") == 0)
        filler(buf, BRIX_OV_DIRNAME, NULL, 0, 0);   /* the passthrough subtree */

    brix_ov_nameset set;
    int opaque = 0;
    rc = brix_overlay_read_upper(&g_ov, ov_rel(path), &set, &opaque);
    if (rc != 0) return rc;

    for (size_t i = 0; ; i++) {                  /* upper entries win */
        char        flag = 0;
        const char *name = brix_ov_nameset_at(&set, i, &flag);
        if (name == NULL) break;
        if (flag == 'u') filler(buf, name, NULL, 0, 0);
    }

    if (!opaque) {                               /* merge the lower listing */
        rw_lowdir_t c = { buf, filler, &set };
        cvmfs_catalog_readdir(brixcvmfs_client()->root_catalog,
                              brixcvmfs_cat_path(path), rw_lowdir_emit, &c);
    }
    brix_ov_nameset_free(&set);
    return 0;
}

/* ---- namespace mutations ------------------------------------------------- */
