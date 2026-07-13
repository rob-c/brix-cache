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

static brix_overlay g_ov;
static int          g_writes_fd = -1;

/* ---- small path/layer helpers ------------------------------------------- */

/* FUSE path → overlay-relative ("" = root) */
static const char *ov_rel(const char *path) {
    return path[0] == '/' ? path + 1 : path;
}

/* FUSE path → .brixwrites-relative when inside the passthrough subtree
 * ("" = the subtree root), else NULL. */
static const char *pt_rel(const char *path) {
    static const size_t n = sizeof(BRIX_OV_DIRNAME) - 1;
    if (strncmp(path + 1, BRIX_OV_DIRNAME, n) != 0) return NULL;
    const char *rest = path + 1 + n;
    if (rest[0] == '\0') return "";
    if (rest[0] == '/')  return rest + 1;
    return NULL;
}

/* "" → "." for *at() calls on the subtree root */
static const char *pt_at(const char *pr) { return pr[0] ? pr : "."; }

/* leaf component of a FUSE path */
static const char *path_leaf(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* overlay vocabulary (and the cache root) may never be created/touched */
static int rw_reserved(const char *path) {
    if (brix_ov_name_reserved(path_leaf(path))) return 1;
    if (strcmp(path, "/.brixcache") == 0) return 1;
    return 0;
}

/* lower-layer resolve: 1 found / 0 absent / -1 error */
static int lower_resolve(const char *path, cvmfs_dirent_t *e) {
    return cvmfs_client_resolve(brixcvmfs_client(), brixcvmfs_cat_path(path),
                                e, brixcvmfs_mono_now());
}

static int lower_is_dir(const cvmfs_dirent_t *e)  { return (e->flags & CVMFS_FLAG_DIR)  != 0; }
static int lower_is_file(const cvmfs_dirent_t *e) { return (e->flags & CVMFS_FLAG_FILE) != 0; }

/* classify shorthand */
static int rw_classify(const char *path, struct stat *st, brix_ov_state *s) {
    return brix_overlay_classify(&g_ov, ov_rel(path), st, s);
}

/* does the union view show anything at `path`? */
static int merged_exists(const char *path) {
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
 * WHAT: one location snapshot of a path across both layers.
 * WHY:  open/unlink/rmdir/rename all need the same (upper state, lower dirent)
 *       pair; resolving it once keeps the per-op error ordering identical and
 *       the handlers small.
 * HOW:  `s`/`st` come from the overlay classify; `lower`/`e` from the CVMFS
 *       catalog resolve (1 found / 0 absent-or-not-consulted).
 */
typedef struct {
    struct stat    st;      /* upper stat, valid when s == BRIX_OV_UPPER */
    brix_ov_state  s;       /* upper / masked / none */
    cvmfs_dirent_t e;       /* lower dirent, valid when lower == 1 */
    int            lower;   /* 1 found / 0 absent (or masked → not consulted) */
} ov_loc_t;

/*
 * WHAT: classify `path` in upper, then resolve lower unless masked.
 * WHY:  mutation ops (unlink, rename source) need the lower dirent even when
 *       upper wins (to decide whether a whiteout is required), but a masked
 *       path returns -ENOENT before the catalog is ever consulted.
 * HOW:  masked short-circuits with lower = 0; catalog errors map to -EIO.
 */
static int ov_locate(const char *path, ov_loc_t *l) {
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
static int ov_locate_visible(const char *path, ov_loc_t *l) {
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
static mode_t rw_lower_dir_mode(void *ud, const char *rel_dir) {
    (void) ud;
    char path[1024];
    snprintf(path, sizeof(path), "/%s", rel_dir);
    cvmfs_dirent_t e;
    if (lower_resolve(path, &e) == 1 && lower_is_dir(&e))
        return e.mode & 07777;
    return 0755;
}

/* ensure the upper parent chain of `path` exists (lower-mirrored modes) */
static int rw_ensure_parents(const char *path) {
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
static int rw_copyup(const char *path, const cvmfs_dirent_t *e) {
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

static int rw_open(const char *path, struct fuse_file_info *fi) {
    return rw_open_common(path, fi->flags, 0644, fi);
}

static int rw_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    return rw_open_common(path, fi->flags | O_CREAT, mode, fi);
}

static int rw_mknod(const char *path, mode_t mode, dev_t dev) {
    (void) dev;
    if (!S_ISREG(mode)) return -EPERM;
    struct fuse_file_info fi = { 0 };
    fi.flags = O_WRONLY | O_CREAT | O_EXCL;
    int rc = rw_open_common(path, fi.flags, mode, &fi);
    if (rc == 0 && fi.fh) close((int) fi.fh - 1);
    return rc;
}

static int rw_read(const char *path, char *buf, size_t size, off_t off,
                   struct fuse_file_info *fi) {
    if (fi != NULL && fi->fh != 0) {
        ssize_t n = pread((int) fi->fh - 1, buf, size, off); /* vfs-seam-allow: FUSE rw_read on local writable CVMFS overlay fd, not export VFS object */
        return n < 0 ? -errno : (int) n;
    }
    return brixcvmfs_op_read(path, buf, size, off, fi);
}

static int rw_write(const char *path, const char *buf, size_t size, off_t off,
                    struct fuse_file_info *fi) {
    (void) path;
    if (fi == NULL || fi->fh == 0) return -EBADF;
    ssize_t n = pwrite((int) fi->fh - 1, buf, size, off); /* vfs-seam-allow: FUSE rw_write on local writable CVMFS overlay fd, not export VFS object */
    return n < 0 ? -errno : (int) n;
}

static int rw_release(const char *path, struct fuse_file_info *fi) {
    (void) path;
    if (fi != NULL && fi->fh != 0) close((int) fi->fh - 1);
    return 0;
}

static int rw_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    (void) path;
    if (fi == NULL || fi->fh == 0) return 0;
    int fd = (int) fi->fh - 1;
    return (datasync ? fdatasync(fd) : fsync(fd)) != 0 ? -errno : 0;
}

static int rw_truncate(const char *path, off_t len, struct fuse_file_info *fi) {
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

static int rw_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
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

static int rw_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
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

static int rw_mkdir(const char *path, mode_t mode) {
    const char *pr = pt_rel(path);
    if (pr != NULL) return mkdirat(g_writes_fd, pr, mode) != 0 ? -errno : 0;
    if (rw_reserved(path)) return -EPERM;
    if (merged_exists(path)) return -EEXIST;

    int rc = rw_ensure_parents(path);
    if (rc != 0) return rc;
    rc = brix_overlay_mkdir(&g_ov, ov_rel(path), mode);
    if (rc != 0) return rc;
    brix_overlay_whiteout_clear(&g_ov, ov_rel(path));

    cvmfs_dirent_t e;                            /* re-created deleted lower dir */
    if (lower_resolve(path, &e) == 1 && lower_is_dir(&e))
        brix_overlay_set_opaque(&g_ov, ov_rel(path));
    return 0;
}

static int rw_unlink(const char *path) {
    const char *pr = pt_rel(path);
    if (pr != NULL) return unlinkat(g_writes_fd, pr, 0) != 0 ? -errno : 0;
    if (rw_reserved(path)) return -ENOENT;       /* invisible vocabulary */

    ov_loc_t l;
    int rc = ov_locate(path, &l);
    if (rc != 0) return rc;
    if (l.s == BRIX_OV_MASKED) return -ENOENT;

    if (l.s == BRIX_OV_UPPER) {
        if (S_ISDIR(l.st.st_mode)) return -EISDIR;
        rc = brix_overlay_unlink_upper(&g_ov, ov_rel(path));
        if (rc != 0) return rc;
        return l.lower == 1 ? brix_overlay_whiteout_set(&g_ov, ov_rel(path)) : 0;
    }
    if (l.lower == 0) return -ENOENT;
    if (lower_is_dir(&l.e)) return -EISDIR;
    return brix_overlay_whiteout_set(&g_ov, ov_rel(path));
}

typedef struct {
    const brix_ov_nameset *set;
    int                    nonempty;
} rw_lowcount_t;

static void rw_lowcount_cb(const cvmfs_dirent_t *e, void *ud) {
    rw_lowcount_t *c = ud;
    if (e->name[0] == '\0') return;
    if (brix_ov_nameset_flag(c->set, e->name) == 'w') return;   /* whiteouted */
    c->nonempty = 1;
}

/*
 * WHAT: rmdir shape check — is `path` a directory in the merged view?
 * WHY:  rmdir must refuse masked/absent paths and non-directories in either
 *       layer, in exactly this order, before the emptiness scan pays for a
 *       catalog listing.
 * HOW:  classify upper first (its errors win), then resolve lower; fills `l`
 *       and `*lower_dir` for the removal step on success.
 */
static int rw_rmdir_shape(const char *path, ov_loc_t *l, int *lower_dir) {
    int rc = rw_classify(path, &l->st, &l->s);
    if (rc != 0) return rc;
    if (l->s == BRIX_OV_MASKED) return -ENOENT;
    if (l->s == BRIX_OV_UPPER && !S_ISDIR(l->st.st_mode)) return -ENOTDIR;

    l->lower = lower_resolve(path, &l->e);
    if (l->lower < 0) return -EIO;
    *lower_dir = l->lower == 1 && lower_is_dir(&l->e);
    if (l->s == BRIX_OV_NONE && !*lower_dir)
        return l->lower == 1 ? -ENOTDIR : -ENOENT;
    return 0;
}

/*
 * WHAT: merged-empty check — does the union view of dir `path` hold anything?
 * WHY:  any real upper entry, or any un-whiteouted lower entry (unless the
 *       dir is opaque), blocks the removal — same rule as kernel overlayfs.
 * HOW:  scan the upper nameset for 'u' entries first; only when that comes up
 *       empty walk the lower listing with the whiteout set as a filter.
 */
static int rw_dir_merged_nonempty(const char *path, int lower_dir, int *nonempty) {
    brix_ov_nameset set;
    int opaque = 0;
    int rc = brix_overlay_read_upper(&g_ov, ov_rel(path), &set, &opaque);
    if (rc != 0) return rc;
    *nonempty = 0;
    for (size_t i = 0; !*nonempty; i++) {
        char        flag = 0;
        const char *name = brix_ov_nameset_at(&set, i, &flag);
        if (name == NULL) break;
        if (flag == 'u') *nonempty = 1;
    }
    if (!*nonempty && lower_dir && !opaque) {
        rw_lowcount_t c = { &set, 0 };
        cvmfs_catalog_readdir(brixcvmfs_client()->root_catalog,
                              brixcvmfs_cat_path(path), rw_lowcount_cb, &c);
        *nonempty = c.nonempty;
    }
    brix_ov_nameset_free(&set);
    return 0;
}

static int rw_rmdir(const char *path) {
    const char *pr = pt_rel(path);
    if (pr != NULL) return unlinkat(g_writes_fd, pr, AT_REMOVEDIR) != 0 ? -errno : 0;
    if (rw_reserved(path)) return -ENOENT;

    ov_loc_t l;
    int lower_dir = 0;
    int rc = rw_rmdir_shape(path, &l, &lower_dir);
    if (rc != 0) return rc;

    int nonempty = 0;
    rc = rw_dir_merged_nonempty(path, lower_dir, &nonempty);
    if (rc != 0) return rc;
    if (nonempty) return -ENOTEMPTY;

    if (l.s == BRIX_OV_UPPER) {
        rc = brix_overlay_rmdir_upper(&g_ov, ov_rel(path));
        if (rc != 0) return rc;
    }
    return lower_dir ? brix_overlay_whiteout_set(&g_ov, ov_rel(path)) : 0;
}

/*
 * WHAT: rename admission checks shared by every union rename.
 * WHY:  flag/vocabulary/NOREPLACE gating is identical for files and dirs and
 *       must run before either side is resolved.
 * HOW:  pure predicate chain, 0 or -err.
 */
static int rw_rename_preflight(const char *from, const char *to, unsigned int flags) {
    if (flags & ~(unsigned int) RENAME_NOREPLACE) return -EINVAL;
    if (rw_reserved(from) || rw_reserved(to)) return -EPERM;
    if ((flags & RENAME_NOREPLACE) && merged_exists(to)) return -EEXIST;
    return 0;
}

/* target sanity: renaming anything onto a visible directory is refused */
static int rw_rename_target_ok(const char *to) {
    ov_loc_t t;
    int rc = ov_locate_visible(to, &t);
    if (rc != 0) return rc;
    if (t.s == BRIX_OV_UPPER && S_ISDIR(t.st.st_mode)) return -EISDIR;
    if (t.lower == 1 && lower_is_dir(&t.e)) return -EISDIR;
    return 0;
}

/*
 * WHAT: the shared rename tail — move the upper entry `from` → `to`.
 * WHY:  files and pure-upper dirs finish identically: mirror the target's
 *       parent chain, move in upper, unmask the target, and (when the source
 *       still exists in lower) whiteout the old name so it disappears.
 * HOW:  `mask_from` says whether lower still shows the source.
 */
static int rw_rename_commit(const char *from, const char *to, int mask_from) {
    int rc = rw_ensure_parents(to);
    if (rc != 0) return rc;
    rc = brix_overlay_rename_upper(&g_ov, ov_rel(from), ov_rel(to));
    if (rc != 0) return rc;
    brix_overlay_whiteout_clear(&g_ov, ov_rel(to));
    return mask_from ? brix_overlay_whiteout_set(&g_ov, ov_rel(from)) : 0;
}

/*
 * WHAT: directory rename — same-layer (pure-upper) fast path only.
 * WHY:  only a pure-upper dir moves atomically; anything still merged with
 *       lower is -EXDEV (mv falls back to copy+delete, exactly like kernel
 *       overlayfs without redirect_dir).
 * HOW:  an opaque upper dir over a lower dir counts as pure-upper.
 */
static int rw_rename_dir(const char *from, const char *to,
                         int from_upper_dir, int from_lower_dir) {
    if (!from_upper_dir) return -EXDEV;
    brix_ov_nameset set;
    int opaque = 0;
    int rc = brix_overlay_read_upper(&g_ov, ov_rel(from), &set, &opaque);
    if (rc != 0) return rc;
    brix_ov_nameset_free(&set);
    if (from_lower_dir && !opaque) return -EXDEV;
    return rw_rename_commit(from, to, from_lower_dir);
}

/*
 * WHAT: file rename — cross-layer copy-up path.
 * WHY:  a lower-only file must be materialised in upper before it can move;
 *       lower symlinks never move (no copy-up semantics for them).
 * HOW:  copy-up when lower-only, then the shared commit tail.
 */
static int rw_rename_file(const char *from, const char *to, const ov_loc_t *f) {
    if (f->s == BRIX_OV_NONE) {
        if (f->lower == 0) return -ENOENT;
        if (!lower_is_file(&f->e)) return -EPERM;  /* lower symlinks don't move */
        int rc = rw_copyup(from, &f->e);
        if (rc != 0) return rc;
    }
    return rw_rename_commit(from, to, f->lower == 1);
}

static int rw_rename(const char *from, const char *to, unsigned int flags) {
    const char *prf = pt_rel(from), *prt = pt_rel(to);
    if ((prf != NULL) != (prt != NULL)) return -EXDEV;   /* no crossing the seam */
    if (prf != NULL)
        return renameat(g_writes_fd, prf, g_writes_fd, prt) != 0 ? -errno : 0;

    int rc = rw_rename_preflight(from, to, flags);
    if (rc != 0) return rc;

    ov_loc_t f;
    rc = ov_locate(from, &f);
    if (rc != 0) return rc;
    if (f.s == BRIX_OV_MASKED) return -ENOENT;

    rc = rw_rename_target_ok(to);
    if (rc != 0) return rc;

    int from_lower_dir = f.lower == 1 && lower_is_dir(&f.e);
    int from_upper_dir = f.s == BRIX_OV_UPPER && S_ISDIR(f.st.st_mode);
    if (from_upper_dir || from_lower_dir)
        return rw_rename_dir(from, to, from_upper_dir, from_lower_dir);
    return rw_rename_file(from, to, &f);
}

static int rw_symlink(const char *target, const char *path) {
    const char *pr = pt_rel(path);
    if (pr != NULL) return symlinkat(target, g_writes_fd, pr) != 0 ? -errno : 0;
    if (rw_reserved(path)) return -EPERM;
    if (merged_exists(path)) return -EEXIST;
    int rc = rw_ensure_parents(path);
    if (rc != 0) return rc;
    rc = brix_overlay_symlink(&g_ov, target, ov_rel(path));
    if (rc != 0) return rc;
    return brix_overlay_whiteout_clear(&g_ov, ov_rel(path));
}

static int rw_readlink(const char *path, char *buf, size_t size) {
    const char *pr = pt_rel(path);
    if (pr != NULL) {
        ssize_t n = readlinkat(g_writes_fd, pt_at(pr), buf, size - 1);
        if (n < 0) return -errno;
        buf[n] = '\0';
        return 0;
    }
    brix_ov_state s;
    struct stat   st;
    int rc = rw_classify(path, &st, &s);
    if (rc != 0) return rc;
    if (s == BRIX_OV_UPPER)  return brix_overlay_readlink(&g_ov, ov_rel(path), buf, size);
    if (s == BRIX_OV_MASKED) return -ENOENT;
    return brixcvmfs_op_readlink(path, buf, size);
}

/* ---- metadata mutations --------------------------------------------------
 * Shared shape: upper → apply; masked → ENOENT; lower file → copy-up then
 * apply; lower dir → materialise the upper dir then apply. */

typedef int (*rw_meta_fn)(const char *rel, void *arg);

static int rw_meta_apply(const char *path, rw_meta_fn apply, void *arg) {
    if (rw_reserved(path)) return -EPERM;

    struct stat   st;
    brix_ov_state s;
    int rc = rw_classify(path, &st, &s);
    if (rc != 0) return rc;
    if (s == BRIX_OV_UPPER)  return apply(ov_rel(path), arg);
    if (s == BRIX_OV_MASKED) return -ENOENT;

    cvmfs_dirent_t e;
    int lower = lower_resolve(path, &e);
    if (lower < 0) return -EIO;
    if (lower == 0) return -ENOENT;

    if (lower_is_dir(&e)) {
        rc = rw_ensure_parents(path);
        if (rc == 0) rc = brix_overlay_mkdirs(&g_ov, ov_rel(path), rw_lower_dir_mode, NULL);
    } else if (lower_is_file(&e)) {
        rc = rw_copyup(path, &e);
    } else {
        return -EOPNOTSUPP;                      /* lower symlink metadata */
    }
    return rc != 0 ? rc : apply(ov_rel(path), arg);
}

static int rw_apply_chmod(const char *rel, void *arg) {
    return brix_overlay_chmod(&g_ov, rel, *(mode_t *) arg);
}

static int rw_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) fi;
    const char *pr = pt_rel(path);
    if (pr != NULL) return fchmodat(g_writes_fd, pt_at(pr), mode, 0) != 0 ? -errno : 0;
    return rw_meta_apply(path, rw_apply_chmod, &mode);
}

static int rw_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    (void) path; (void) fi;
    /* unprivileged FUSE: identity changes can't be honored; no-ops succeed */
    return (uid == (uid_t) -1 && gid == (gid_t) -1) ? 0 : -EPERM;
}

static int rw_apply_utimens(const char *rel, void *arg) {
    return brix_overlay_utimens(&g_ov, rel, (const struct timespec *) arg);
}

static int rw_utimens(const char *path, const struct timespec tv[2],
                      struct fuse_file_info *fi) {
    if (fi != NULL && fi->fh != 0)
        return futimens((int) fi->fh - 1, tv) != 0 ? -errno : 0;
    const char *pr = pt_rel(path);
    if (pr != NULL)
        return utimensat(g_writes_fd, pt_at(pr), tv, AT_SYMLINK_NOFOLLOW) != 0 ? -errno : 0;
    return rw_meta_apply(path, rw_apply_utimens, (void *) tv);
}

/* ---- statfs / xattr ------------------------------------------------------ */

static int rw_statfs(const char *path, struct statvfs *sv) {
    if (fstatvfs(g_writes_fd, sv) == 0) {        /* writes land here → report it */
        sv->f_namemax = 255;
        return 0;
    }
    return brixcvmfs_op_statfs(path, sv);
}

/* answer for the user.overlay magic attribute, or NULL when not ours */
static const char *rw_overlay_xattr(const char *path) {
    struct stat   st;
    brix_ov_state s;
    if (rw_classify(path, &st, &s) != 0) return NULL;
    if (s == BRIX_OV_MASKED) return NULL;
    cvmfs_dirent_t e;
    int lower = lower_resolve(path, &e);
    if (s == BRIX_OV_UPPER) return lower == 1 ? "modified" : "new";
    return lower == 1 ? "lower" : NULL;
}

static int rw_getxattr(const char *path, const char *name, char *value, size_t size) {
    if (pt_rel(path) != NULL) return -ENODATA;
    if (strcmp(name, "user.overlay") == 0) {
        const char *v = rw_overlay_xattr(path);
        if (v == NULL) return -ENODATA;
        size_t n = strlen(v);
        if (size == 0) return (int) n;           /* size probe */
        if (n > size)  return -ERANGE;
        memcpy(value, v, n);
        return (int) n;
    }
    brix_ov_state s;
    struct stat   st;
    if (rw_classify(path, &st, &s) != 0) return -ENODATA;
    if (s == BRIX_OV_UPPER)  return -ENODATA;    /* cvmfs attrs are lower-only */
    if (s == BRIX_OV_MASKED) return -ENODATA;
    return brixcvmfs_op_getxattr(path, name, value, size);
}

static int rw_listxattr(const char *path, char *list, size_t size) {
    static const char mine[] = "user.overlay";
    int n = brixcvmfs_op_listxattr(path, NULL, 0);
    if (n < 0) n = 0;
    size_t total = (size_t) n + sizeof(mine);
    if (size == 0) return (int) total;
    if (total > size) return -ERANGE;
    if (n > 0 && brixcvmfs_op_listxattr(path, list, size) != n) return -EIO;
    memcpy(list + n, mine, sizeof(mine));
    return (int) total;
}

/* ---- the ops table + lifecycle ------------------------------------------- */

const struct fuse_operations brixcvmfs_rw_ops = {
    .getattr   = rw_getattr,
    .readdir   = rw_readdir,
    .open      = rw_open,
    .create    = rw_create,
    .mknod     = rw_mknod,
    .read      = rw_read,
    .write     = rw_write,
    .release   = rw_release,
    .fsync     = rw_fsync,
    .truncate  = rw_truncate,
    .mkdir     = rw_mkdir,
    .unlink    = rw_unlink,
    .rmdir     = rw_rmdir,
    .rename    = rw_rename,
    .symlink   = rw_symlink,
    .readlink  = rw_readlink,
    .chmod     = rw_chmod,
    .chown     = rw_chown,
    .utimens   = rw_utimens,
    .statfs    = rw_statfs,
    .getxattr  = rw_getxattr,
    .listxattr = rw_listxattr,
};

int brixcvmfs_setup_rw(const char *mnt, const char *writes_override) {
    char dir[600];
    if (writes_override != NULL && writes_override[0] != '\0') {
        snprintf(dir, sizeof(dir), "%s", writes_override);
    } else {
        mkdir(mnt, 0755);                        /* ensure the mountpoint exists */
        snprintf(dir, sizeof(dir), "%s/" BRIX_OV_DIRNAME, mnt);
    }
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "brixcvmfs: cannot create overlay dir %s\n", dir);
        return -1;
    }
    g_writes_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (g_writes_fd < 0 || brix_overlay_init(&g_ov, g_writes_fd) != 0) {
        fprintf(stderr, "brixcvmfs: overlay at %s unusable\n", dir);
        if (g_writes_fd >= 0) { close(g_writes_fd); g_writes_fd = -1; }
        return -1;
    }
    return 0;
}

void brixcvmfs_teardown_rw(void) {
    brix_overlay_close(&g_ov);
    if (g_writes_fd >= 0) close(g_writes_fd);
    g_writes_fd = -1;
}

/* brixMount driver entry for `cvmfs-rw` */
int brixcvmfs_main(int argc, char **argv);        /* the ro front-end owns it */

int brixcvmfs_rw_main(int argc, char **argv) {
    brixcvmfs_rw = 1;
    return brixcvmfs_main(argc, argv);
}
