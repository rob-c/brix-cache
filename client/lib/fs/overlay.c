/*
 * overlay.c — writable union overlay core for brixMount cvmfs-rw.
 *
 * WHAT: implements the upper-tree primitives declared in overlay.h: the
 *       O_NOFOLLOW component walk, union classification, whiteout/opaque
 *       markers, mutations, atomic copy-up, readdir nameset, and CLI cores.
 * WHY:  one small, FUSE/CVMFS-free translation unit owns every union corner
 *       case so they are provable on plain tmp directories.
 * HOW:  ov_split() peels validated path components (".", "..", empty and
 *       oversized components are refused); ov_walk_parent() descends dir by
 *       dir with O_NOFOLLOW|O_DIRECTORY so planted symlinks dead-end instead
 *       of escaping; everything else composes those two.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fs/overlay.h"
#include "overlay_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/xattr.h>


/* ---- path-component parsing --------------------------------------------- */

/* Peel the leading component of *relp into name[]; advances *relp past the
 * '/' (or leaves it NULL on the last component). Returns 1 = more components
 * follow, 0 = this was the leaf, -EINVAL = empty/"."/".."/oversized. */
static int ov_split(const char **relp, char *name, size_t cap) {
    const char *rel   = *relp;
    const char *slash = strchr(rel, '/');
    size_t      n     = slash ? (size_t) (slash - rel) : strlen(rel);

    if (n == 0 || n >= cap) return -EINVAL;
    memcpy(name, rel, n);
    name[n] = '\0';
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return -EINVAL;
    *relp = slash ? slash + 1 : NULL;
    return slash ? 1 : 0;
}

int brix_ov_name_reserved(const char *name) {
    if (strncmp(name, BRIX_OV_WH_PREFIX, sizeof(BRIX_OV_WH_PREFIX) - 1) == 0)  return 1;
    if (strncmp(name, BRIX_OV_TMP_PREFIX, sizeof(BRIX_OV_TMP_PREFIX) - 1) == 0) return 1;
    if (strcmp(name, BRIX_OV_OPQ_NAME) == 0) return 1;
    return 0;
}

/* whiteout marker name for a component: ".brix.wh.<name>" */
static void ov_wh_name(const char *name, char *buf, size_t cap) {
    snprintf(buf, cap, BRIX_OV_WH_PREFIX "%s", name);
}

/* marker present in dirfd? (lstat semantics; never follows) */
static int ov_marker_at(int dirfd, const char *marker) {
    struct stat st;
    return fstatat(dirfd, marker, &st, AT_SYMLINK_NOFOLLOW) == 0;
}

/* ---- the O_NOFOLLOW walk ------------------------------------------------- */

/* ---- Open (optionally create) one directory component of the walk ----
 *
 * WHAT: Opens child `name` under `dirfd` with O_NOFOLLOW|O_DIRECTORY. When
 *       `mk` is set and the child is missing, it is created — mode_fn(ud,
 *       prefix) supplies the mode, or 0755 when mode_fn is NULL — then
 *       reopened. Returns the child dirfd (caller closes) or -errno. `dirfd`
 *       is left open for the caller to close in every case.
 *
 * WHY:  Factoring the create-if-missing-then-reopen step keeps ov_walk_parent_mk
 *       a flat descent loop and confines the mkdir race handling (a racing
 *       creator yielding EEXIST is benign) to one place.
 *
 * HOW:  1. Try an O_NOFOLLOW openat of the child directory.
 *       2. On ENOENT with `mk`, mkdirat with the computed mode (EEXIST is
 *          tolerated) and reopen.
 *       3. Map any residual failure to -errno; errno reflects the last syscall.
 */
static int ov_descend_dir(int dirfd, const char *name, int mk,
                          mode_t (*mode_fn)(void *ud, const char *rel_dir),
                          void *ud, const char *prefix) {
    int next = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0 && mk && errno == ENOENT) {
        mode_t m = mode_fn ? mode_fn(ud, prefix) : 0755;
        if (mkdirat(dirfd, name, m) != 0 && errno != EEXIST) return -errno;
        next = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    return next < 0 ? -errno : next;
}

/* Open the parent directory of `rel`'s leaf, descending from upper_fd one
 * component at a time with O_NOFOLLOW|O_DIRECTORY (symlinks dead-end). With
 * `mk`, missing intermediate dirs are created (mode_fn(ud, prefix) or 0755).
 * The leaf component is stored in leaf[]. Returns the parent dirfd (caller
 * closes) or -errno. rel must be non-empty. */
int ov_walk_parent_mk(const brix_overlay *ov, const char *rel,
                             char *leaf, size_t leafcap, int mk,
                             mode_t (*mode_fn)(void *ud, const char *rel_dir),
                             void *ud) {
    if (rel == NULL || rel[0] == '\0') return -EINVAL;

    int cur = openat(ov->upper_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cur < 0) return -errno;

    char        prefix[4096];   /* walked prefix, for mode_fn */
    size_t      plen = 0;
    const char *p    = rel;
    prefix[0] = '\0';

    for (;;) {
        int more = ov_split(&p, leaf, leafcap);
        if (more < 0) { close(cur); return more; }
        if (more == 0) return cur;                 /* cur = the leaf's parent */

        size_t ll = strlen(leaf);
        if (plen + ll + 2 < sizeof(prefix)) {
            if (plen > 0) prefix[plen++] = '/';
            memcpy(prefix + plen, leaf, ll + 1);
            plen += ll;
        }

        int next = ov_descend_dir(cur, leaf, mk, mode_fn, ud, prefix);
        close(cur);
        if (next < 0) return next;
        cur = next;
    }
}

static int ov_walk_parent(const brix_overlay *ov, const char *rel,
                          char *leaf, size_t leafcap) {
    return ov_walk_parent_mk(ov, rel, leaf, leafcap, 0, NULL, NULL);
}

/* ---- lifecycle ----------------------------------------------------------- */

int brix_overlay_init(brix_overlay *ov, int writes_fd) {
    ov->writes_fd = writes_fd;
    ov->upper_fd  = -1;
    if (mkdirat(writes_fd, BRIX_OV_UPPER_DIRNAME, 0755) != 0 && errno != EEXIST)
        return -errno;
    ov->upper_fd = openat(writes_fd, BRIX_OV_UPPER_DIRNAME,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    return ov->upper_fd < 0 ? -errno : 0;
}

void brix_overlay_close(brix_overlay *ov) {
    if (ov->upper_fd >= 0) close(ov->upper_fd);
    ov->upper_fd = -1;
}

/* ---- classification ------------------------------------------------------ */

/* ---- Classify the repo root (empty rel) as the upper directory ----
 *
 * WHAT: Reports the union root as BRIX_OV_UPPER, filling *st from the upper
 *       dirfd when st is non-NULL. Returns 0, or -errno if the fstat fails.
 *
 * WHY:  The empty relative path names the union root, which is always the
 *       upper directory itself; handling it separately keeps the component
 *       walk in brix_overlay_classify free of the root special case.
 *
 * HOW:  1. fstat the upper dirfd into *st when a stat buffer was supplied.
 *       2. Set *state to BRIX_OV_UPPER and return success.
 */
static int ov_classify_root(const brix_overlay *ov, struct stat *st,
                            brix_ov_state *state) {
    if (st != NULL && fstat(ov->upper_fd, st) != 0) return -errno;
    *state = BRIX_OV_UPPER;
    return 0;
}

/* ---- Descend into an upper subdirectory during classification ----
 *
 * WHAT: Opens directory component `name` under `cur` with O_NOFOLLOW and
 *       closes `cur` unconditionally. Sets *opaque when the child carries the
 *       opaque marker. Returns the child dirfd (caller closes) or -errno.
 *
 * WHY:  The classify walk must note an opaque directory the moment it enters
 *       one and must never follow a planted symlink; isolating the descend
 *       keeps that ordering explicit and the walk loop flat.
 *
 * HOW:  1. O_NOFOLLOW openat of the child directory, then close the parent.
 *       2. On failure return -errno.
 *       3. Probe for the opaque marker in the child and record it in *opaque.
 */
static int ov_descend_child(int cur, const char *name, int *opaque) {
    int next = openat(cur, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(cur);
    if (next < 0) return -errno;
    if (ov_marker_at(next, BRIX_OV_OPQ_NAME)) *opaque = 1;
    return next;
}

/* Walk `rel` from the upper root and decide how the union sees it: a whiteout
 * on any component, an opaque ancestor, or a non-dir upper component shadowing
 * the remainder all mask the lower layer; a leaf found in upper wins; anything
 * else falls through to lower. */
int brix_overlay_classify(const brix_overlay *ov, const char *rel,
                          struct stat *st, brix_ov_state *state) {
    *state = BRIX_OV_NONE;
    if (rel == NULL) return -EINVAL;

    if (rel[0] == '\0')                         /* the repo root is upper/ */
        return ov_classify_root(ov, st, state);

    int cur = openat(ov->upper_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cur < 0) return -errno;

    int         opaque = 0;
    const char *p      = rel;
    char        name[OV_NAME_MAX], wh[OV_NAME_MAX + sizeof(BRIX_OV_WH_PREFIX)];

    for (;;) {
        int more = ov_split(&p, name, sizeof(name));
        if (more < 0) { close(cur); return more; }

        ov_wh_name(name, wh, sizeof(wh));
        if (ov_marker_at(cur, wh)) {            /* whiteouted at this level */
            close(cur);
            *state = BRIX_OV_MASKED;
            return 0;
        }

        struct stat cst;
        if (fstatat(cur, name, &cst, AT_SYMLINK_NOFOLLOW) != 0) {
            close(cur);                          /* not in upper from here on */
            *state = opaque ? BRIX_OV_MASKED : BRIX_OV_NONE;
            return 0;
        }

        if (more == 0) {                         /* leaf present in upper */
            close(cur);
            if (st != NULL) *st = cst;
            *state = BRIX_OV_UPPER;
            return 0;
        }

        if (!S_ISDIR(cst.st_mode)) {             /* upper non-dir shadows all below */
            close(cur);
            *state = BRIX_OV_MASKED;
            return 0;
        }

        cur = ov_descend_child(cur, name, &opaque);
        if (cur < 0) return cur;
    }
}

/* ---- whiteout markers ---------------------------------------------------- */

int brix_overlay_whiteout(const brix_overlay *ov, const char *rel) {
    char leaf[OV_NAME_MAX], wh[OV_NAME_MAX + sizeof(BRIX_OV_WH_PREFIX)];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent == -ENOENT) return 0;            /* no upper parent → no marker */
    if (parent < 0) return parent;
    ov_wh_name(leaf, wh, sizeof(wh));
    int present = ov_marker_at(parent, wh);
    close(parent);
    return present;
}

int brix_overlay_whiteout_set(const brix_overlay *ov, const char *rel) {
    char leaf[OV_NAME_MAX], wh[OV_NAME_MAX + sizeof(BRIX_OV_WH_PREFIX)];
    int  parent = ov_walk_parent_mk(ov, rel, leaf, sizeof(leaf), 1, NULL, NULL);
    if (parent < 0) return parent;
    ov_wh_name(leaf, wh, sizeof(wh));
    int fd = openat(parent, wh, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
    int rc = (fd < 0 && errno != EEXIST) ? -errno : 0;
    if (fd >= 0) close(fd);
    close(parent);
    return rc;
}

/* Open the upper directory `rel_dir` itself ("" = the upper root). Returns a
 * dirfd (caller closes) or -errno. */
int ov_open_dir(const brix_overlay *ov, const char *rel_dir) {
    if (rel_dir[0] == '\0')
        return openat(ov->upper_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel_dir, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    int fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int rc = fd < 0 ? -errno : fd;
    close(parent);
    return rc;
}

int brix_overlay_mkdirs(const brix_overlay *ov, const char *rel_dir,
                        mode_t (*mode_fn)(void *ud, const char *rel_dir),
                        void *ud) {
    if (rel_dir[0] == '\0') return 0;            /* the upper root exists */

    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent_mk(ov, rel_dir, leaf, sizeof(leaf), 1, mode_fn, ud);
    if (parent < 0) return parent;

    mode_t m = mode_fn ? mode_fn(ud, rel_dir) : 0755;
    int    rc = 0;
    if (mkdirat(parent, leaf, m) != 0 && errno != EEXIST) rc = -errno;

    struct stat st;                              /* an existing non-dir leaf is an error */
    if (rc == 0 && fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0
        && !S_ISDIR(st.st_mode))
        rc = -ENOTDIR;
    close(parent);
    return rc;
}

/* Resolve rel's parent with the O_NOFOLLOW walk, run op(parent, leaf, arg),
 * close the parent, and return op's result. Every single-leaf operation
 * shares this walk/close discipline. */
typedef int (*ov_leaf_op)(int parent, const char *leaf, void *arg);

static int ov_at_leaf(const brix_overlay *ov, const char *rel,
                      ov_leaf_op op, void *arg) {
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    int rc = op(parent, leaf, arg);
    close(parent);
    return rc;
}

struct ov_open_args { int oflags; mode_t mode; };

static int ov_op_open(int parent, const char *leaf, void *arg) {
    const struct ov_open_args *a = arg;
    int fd = openat(parent, leaf, a->oflags | O_NOFOLLOW | O_CLOEXEC, a->mode);
    return fd < 0 ? -errno : fd;
}

int brix_overlay_open(const brix_overlay *ov, const char *rel,
                      int oflags, mode_t mode) {
    struct ov_open_args a = { oflags, mode };
    return ov_at_leaf(ov, rel, ov_op_open, &a);
}

static int ov_op_mkdir(int parent, const char *leaf, void *arg) {
    return mkdirat(parent, leaf, *(mode_t *) arg) != 0 ? -errno : 0;
}

int brix_overlay_mkdir(const brix_overlay *ov, const char *rel, mode_t mode) {
    return ov_at_leaf(ov, rel, ov_op_mkdir, &mode);
}

int brix_overlay_set_opaque(const brix_overlay *ov, const char *rel_dir) {
    int dir = ov_open_dir(ov, rel_dir);
    if (dir < 0) return dir;
    int fd = openat(dir, BRIX_OV_OPQ_NAME, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
    int rc = (fd < 0 && errno != EEXIST) ? -errno : 0;
    if (fd >= 0) close(fd);
    close(dir);
    return rc;
}

static int ov_op_unlinkat(int parent, const char *leaf, void *arg) {
    return unlinkat(parent, leaf, *(int *) arg) != 0 ? -errno : 0;
}

int brix_overlay_unlink_upper(const brix_overlay *ov, const char *rel) {
    int flags = 0;
    return ov_at_leaf(ov, rel, ov_op_unlinkat, &flags);
}

/* Unlink every overlay marker inside dirfd; a real entry → -ENOTEMPTY. */
static int ov_clear_markers(int dirfd) {
    int lfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (lfd < 0) return -errno;
    DIR *d = fdopendir(lfd);                     /* owns lfd from here */
    if (d == NULL) { int e = errno; close(lfd); return -e; }

    int            rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (!brix_ov_name_reserved(e->d_name)) { rc = -ENOTEMPTY; break; }
        if (unlinkat(dirfd, e->d_name, 0) != 0) { rc = -errno; break; }
    }
    closedir(d);
    return rc;
}

int brix_overlay_rmdir_upper(const brix_overlay *ov, const char *rel) {
    int dir = ov_open_dir(ov, rel);
    if (dir < 0) return dir;
    int rc = ov_clear_markers(dir);
    close(dir);
    if (rc != 0) return rc;

    int flags = AT_REMOVEDIR;
    return ov_at_leaf(ov, rel, ov_op_unlinkat, &flags);
}

int brix_overlay_rename_upper(const brix_overlay *ov, const char *from,
                              const char *to) {
    char fleaf[OV_NAME_MAX], tleaf[OV_NAME_MAX];
    int  fparent = ov_walk_parent(ov, from, fleaf, sizeof(fleaf));
    if (fparent < 0) return fparent;
    int tparent = ov_walk_parent(ov, to, tleaf, sizeof(tleaf));
    if (tparent < 0) { close(fparent); return tparent; }
    int rc = renameat(fparent, fleaf, tparent, tleaf) != 0 ? -errno : 0;
    close(fparent);
    close(tparent);
    return rc;
}

static int ov_op_symlink(int parent, const char *leaf, void *arg) {
    return symlinkat(arg, parent, leaf) != 0 ? -errno : 0;
}

int brix_overlay_symlink(const brix_overlay *ov, const char *target,
                         const char *rel) {
    return ov_at_leaf(ov, rel, ov_op_symlink, (void *) target);
}

struct ov_rlink_args { char *buf; size_t n; };

static int ov_op_readlink(int parent, const char *leaf, void *arg) {
    struct ov_rlink_args *a = arg;
    ssize_t len = readlinkat(parent, leaf, a->buf, a->n);
    if (len < 0) return -errno;
    if ((size_t) len >= a->n) return -ENAMETOOLONG;
    a->buf[len] = '\0';
    return 0;
}

int brix_overlay_readlink(const brix_overlay *ov, const char *rel,
                          char *buf, size_t n) {
    struct ov_rlink_args a = { buf, n };
    return ov_at_leaf(ov, rel, ov_op_readlink, &a);
}

static int ov_op_chmod(int parent, const char *leaf, void *arg) {
    struct stat st;
    if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) return -errno;
    if (S_ISLNK(st.st_mode)) return -EOPNOTSUPP;   /* mode on a link is meaningless */
    return fchmodat(parent, leaf, *(mode_t *) arg, 0) != 0 ? -errno : 0;
}

int brix_overlay_chmod(const brix_overlay *ov, const char *rel, mode_t mode) {
    return ov_at_leaf(ov, rel, ov_op_chmod, &mode);
}

static int ov_op_utimens(int parent, const char *leaf, void *arg) {
    return utimensat(parent, leaf, arg, AT_SYMLINK_NOFOLLOW) != 0 ? -errno : 0;
}

int brix_overlay_utimens(const brix_overlay *ov, const char *rel,
                         const struct timespec tv[2]) {
    return ov_at_leaf(ov, rel, ov_op_utimens, (void *) tv);
}

int brix_overlay_truncate(const brix_overlay *ov, const char *rel, off_t len) {
    int fd = brix_overlay_open(ov, rel, O_WRONLY, 0);
    if (fd < 0) return fd;
    int rc = ftruncate(fd, len) != 0 ? -errno : 0;
    close(fd);
    return rc;
}

int brix_overlay_whiteout_clear(const brix_overlay *ov, const char *rel) {
    char leaf[OV_NAME_MAX], wh[OV_NAME_MAX + sizeof(BRIX_OV_WH_PREFIX)];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent == -ENOENT) return 0;            /* nothing to clear */
    if (parent < 0) return parent;
    ov_wh_name(leaf, wh, sizeof(wh));
    int rc = (unlinkat(parent, wh, 0) != 0 && errno != ENOENT) ? -errno : 0;
    close(parent);
    return rc;
}
