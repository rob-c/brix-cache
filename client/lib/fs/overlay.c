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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/xattr.h>

#define OV_NAME_MAX 256   /* one path component incl. NUL */

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
static int ov_walk_parent_mk(const brix_overlay *ov, const char *rel,
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
static int ov_open_dir(const brix_overlay *ov, const char *rel_dir) {
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

int brix_overlay_open(const brix_overlay *ov, const char *rel,
                      int oflags, mode_t mode) {
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    int fd = openat(parent, leaf, oflags | O_NOFOLLOW | O_CLOEXEC, mode);
    int rc = fd < 0 ? -errno : fd;
    close(parent);
    return rc;
}

int brix_overlay_mkdir(const brix_overlay *ov, const char *rel, mode_t mode) {
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    int rc = mkdirat(parent, leaf, mode) != 0 ? -errno : 0;
    close(parent);
    return rc;
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

int brix_overlay_unlink_upper(const brix_overlay *ov, const char *rel) {
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    int rc = unlinkat(parent, leaf, 0) != 0 ? -errno : 0;
    close(parent);
    return rc;
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

    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    rc = unlinkat(parent, leaf, AT_REMOVEDIR) != 0 ? -errno : 0;
    close(parent);
    return rc;
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

int brix_overlay_symlink(const brix_overlay *ov, const char *target,
                         const char *rel) {
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    int rc = symlinkat(target, parent, leaf) != 0 ? -errno : 0;
    close(parent);
    return rc;
}

int brix_overlay_readlink(const brix_overlay *ov, const char *rel,
                          char *buf, size_t n) {
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    ssize_t len = readlinkat(parent, leaf, buf, n);
    close(parent);
    if (len < 0) return -errno;
    if ((size_t) len >= n) return -ENAMETOOLONG;
    buf[len] = '\0';
    return 0;
}

int brix_overlay_chmod(const brix_overlay *ov, const char *rel, mode_t mode) {
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;

    struct stat st;
    int rc = 0;
    if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) rc = -errno;
    else if (S_ISLNK(st.st_mode)) rc = -EOPNOTSUPP;   /* mode on a link is meaningless */
    else if (fchmodat(parent, leaf, mode, 0) != 0) rc = -errno;
    close(parent);
    return rc;
}

int brix_overlay_utimens(const brix_overlay *ov, const char *rel,
                         const struct timespec tv[2]) {
    char leaf[OV_NAME_MAX];
    int  parent = ov_walk_parent(ov, rel, leaf, sizeof(leaf));
    if (parent < 0) return parent;
    int rc = utimensat(parent, leaf, tv, AT_SYMLINK_NOFOLLOW) != 0 ? -errno : 0;
    close(parent);
    return rc;
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

/* ---- copy-up ------------------------------------------------------------- */

#define OV_COPYUP_CHUNK (1024u * 1024u)

/* Stream `size` lower bytes of `rel` into fd via the injected reader. A short
 * read before `size` is a lower-layer lie → -EIO. */
static int ov_copyup_stream(int fd, const char *rel, uint64_t size,
                            brix_ov_read_fn read_lower, void *ud) {
    unsigned char *buf = malloc(OV_COPYUP_CHUNK);
    if (buf == NULL) return -ENOMEM;

    uint64_t off = 0;
    int      rc  = 0;
    while (rc == 0 && off < size) {
        size_t want = size - off > OV_COPYUP_CHUNK ? OV_COPYUP_CHUNK
                                                   : (size_t) (size - off);
        size_t got  = 0;
        rc = read_lower(ud, rel, off, want, buf, &got);
        if (rc == 0 && got == 0) rc = -EIO;         /* premature EOF */
        for (size_t done = 0; rc == 0 && done < got; ) {
            ssize_t w = pwrite(fd, buf + done, got - done, (off_t) (off + done)); /* vfs-seam-allow: copy-up write to upper writable overlay layer, not export data */
            if (w < 0) rc = -errno;
            else done += (size_t) w;
        }
        off += got;
    }
    free(buf);
    return rc;
}

int brix_overlay_copyup(const brix_overlay *ov, const char *rel,
                        const struct stat *lower_st,
                        brix_ov_read_fn read_lower, void *ud) {
    char leaf[OV_NAME_MAX], tmp[OV_NAME_MAX + sizeof(BRIX_OV_TMP_PREFIX)];
    int  parent = ov_walk_parent_mk(ov, rel, leaf, sizeof(leaf), 1, NULL, NULL);
    if (parent < 0) return parent;

    snprintf(tmp, sizeof(tmp), BRIX_OV_TMP_PREFIX "%s", leaf);
    int fd = openat(parent, tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                    lower_st->st_mode & 07777);
    if (fd < 0) { int e = errno; close(parent); return -e; }

    /* the openat mode is umask-filtered — restate the exact lower bits */
    int rc = fchmod(fd, lower_st->st_mode & 07777) != 0 ? -errno : 0;
    if (rc == 0)
        rc = ov_copyup_stream(fd, rel, (uint64_t) lower_st->st_size, read_lower, ud);
    if (rc == 0) {
        struct timespec tv[2] = { { lower_st->st_mtime, 0 }, { lower_st->st_mtime, 0 } };
        if (futimens(fd, tv) != 0) rc = -errno;
    }
    close(fd);

    if (rc == 0 && renameat(parent, tmp, parent, leaf) != 0) rc = -errno;
    if (rc != 0) unlinkat(parent, tmp, 0);          /* leave no torn trace */
    close(parent);

    return rc == 0 ? brix_overlay_whiteout_clear(ov, rel) : rc;
}

/* ---- merged-readdir support ---------------------------------------------- */

static int ov_nameset_add(brix_ov_nameset *s, char flag, const char *name) {
    size_t need = strlen(name) + 2;              /* flag + name + NUL */
    if (s->used + need > s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 512;
        while (ncap < s->used + need) ncap *= 2;
        char *nb = realloc(s->buf, ncap);
        if (nb == NULL) return -ENOMEM;
        s->buf = nb;
        s->cap = ncap;
    }
    s->buf[s->used] = flag;
    memcpy(s->buf + s->used + 1, name, need - 1);
    s->used += need;
    s->count++;
    return 0;
}

int brix_overlay_read_upper(const brix_overlay *ov, const char *rel,
                            brix_ov_nameset *set, int *opaque) {
    memset(set, 0, sizeof(*set));
    *opaque = 0;

    int dir = ov_open_dir(ov, rel);
    if (dir == -ENOENT || dir == -ENOTDIR) return 0;   /* nothing in upper */
    if (dir < 0) return dir;

    DIR *d = fdopendir(dir);                     /* owns dir from here */
    if (d == NULL) { int e = errno; close(dir); return -e; }

    int            rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (strcmp(n, ".") == 0 || strcmp(n, "..") == 0) continue;
        if (strcmp(n, BRIX_OV_OPQ_NAME) == 0) { *opaque = 1; continue; }
        if (strncmp(n, BRIX_OV_TMP_PREFIX, sizeof(BRIX_OV_TMP_PREFIX) - 1) == 0) continue;
        if (strncmp(n, BRIX_OV_WH_PREFIX, sizeof(BRIX_OV_WH_PREFIX) - 1) == 0)
            rc = ov_nameset_add(set, 'w', n + sizeof(BRIX_OV_WH_PREFIX) - 1);
        else
            rc = ov_nameset_add(set, 'u', n);
    }
    closedir(d);
    if (rc != 0) brix_ov_nameset_free(set);
    return rc;
}

char brix_ov_nameset_flag(const brix_ov_nameset *s, const char *name) {
    for (size_t off = 0; off < s->used; ) {
        char        fl = s->buf[off];
        const char *nm = s->buf + off + 1;
        if (strcmp(nm, name) == 0) return fl;
        off += strlen(nm) + 2;
    }
    return 0;
}

const char *brix_ov_nameset_at(const brix_ov_nameset *s, size_t i, char *flag) {
    size_t idx = 0;
    for (size_t off = 0; off < s->used; idx++) {
        const char *nm = s->buf + off + 1;
        if (idx == i) {
            if (flag != NULL) *flag = s->buf[off];
            return nm;
        }
        off += strlen(nm) + 2;
    }
    return NULL;
}

void brix_ov_nameset_free(brix_ov_nameset *s) {
    free(s->buf);
    memset(s, 0, sizeof(*s));
}

/* ---- CLI cores (--overlay-list / --overlay-reset) ------------------------ */

/* Wrong-mountpoint guard: <mountdir>/.brixwrites/upper must be a directory.
 * On success *upper_out (asprintf'd, caller frees) holds its path. */
static int ov_cli_guard(const char *mountdir, char **upper_out) {
    if (asprintf(upper_out, "%s/" BRIX_OV_DIRNAME "/" BRIX_OV_UPPER_DIRNAME,
                 mountdir) < 0)
        return 1;
    struct stat st;
    if (lstat(*upper_out, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    fprintf(stderr, "brixMount: no " BRIX_OV_DIRNAME
            " overlay under %s (not a cvmfs-rw mountpoint?)\n", mountdir);
    free(*upper_out);
    *upper_out = NULL;
    return 2;
}

/* Change kind for an upper file: the live mount answers the user.overlay
 * magic xattr ("new"/"modified"); unmounted raw trees have none → "upper". */
static void ov_cli_kind(const char *mountdir, const char *rel,
                        char *kind, size_t cap) {
    char   *p = NULL;
    ssize_t n = -1;
    if (asprintf(&p, "%s/%s", mountdir, rel) >= 0) {
        n = lgetxattr(p, "user.overlay", kind, cap - 1);
        free(p);
    }
    if (n > 0) kind[n] = '\0';
    else       snprintf(kind, cap, "upper");
}

/* Forward decl: ov_cli_list_dir and ov_cli_list_entry recurse into each other
 * (a subdirectory entry descends via ov_cli_list_dir). */
static int ov_cli_list_entry(const char *mountdir, const char *upper_root,
                             const char *rel, const char *dirp,
                             const char *name, FILE *out);

static int ov_cli_list_dir(const char *mountdir, const char *upper_root,
                           const char *rel, FILE *out) {
    char *dirp = NULL;
    if (asprintf(&dirp, "%s%s%s", upper_root, rel[0] ? "/" : "", rel) < 0) return 1;
    DIR *d = opendir(dirp);
    if (d == NULL) { free(dirp); return 1; }

    int            rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        rc = ov_cli_list_entry(mountdir, upper_root, rel, dirp, e->d_name, out);
    }
    closedir(d);
    free(dirp);
    return rc;
}

/* ---- Emit one upper-tree entry during --overlay-list ----
 *
 * WHAT: Classifies dirent `name` in the upper directory `dirp` (union path
 *       `rel`): "." "..", the opaque marker and tmp files are skipped; a
 *       whiteout prints a "deleted" line; a subdirectory prints "dir" and
 *       recurses; any other entry prints its change kind. Returns 0, or 1 on
 *       an allocation failure (which stops the enclosing scan).
 *
 * WHY:  Splitting the per-entry decision ladder out of ov_cli_list_dir keeps
 *       each function small and single-purpose while preserving the exact
 *       skip/whiteout/recurse ordering the listing relies on.
 *
 * HOW:  1. Return early for reserved/skipped names.
 *       2. Print and return for a whiteout marker.
 *       3. Build the child union path and absolute path; on OOM free and fail.
 *       4. Recurse into a subdirectory, else print the file's change kind.
 */
static int ov_cli_list_entry(const char *mountdir, const char *upper_root,
                             const char *rel, const char *dirp,
                             const char *name, FILE *out) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
    if (strcmp(name, BRIX_OV_OPQ_NAME) == 0) return 0;
    if (strncmp(name, BRIX_OV_TMP_PREFIX, sizeof(BRIX_OV_TMP_PREFIX) - 1) == 0) return 0;

    if (strncmp(name, BRIX_OV_WH_PREFIX, sizeof(BRIX_OV_WH_PREFIX) - 1) == 0) {
        fprintf(out, "deleted %s%s%s\n", rel, rel[0] ? "/" : "",
                name + sizeof(BRIX_OV_WH_PREFIX) - 1);
        return 0;
    }

    char *crel = NULL, *full = NULL;
    if (asprintf(&crel, "%s%s%s", rel, rel[0] ? "/" : "", name) < 0
        || asprintf(&full, "%s/%s", dirp, name) < 0) {
        free(crel);
        return 1;
    }

    int         rc = 0;
    struct stat st;
    if (lstat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
        fprintf(out, "dir %s\n", crel);
        rc = ov_cli_list_dir(mountdir, upper_root, crel, out);
    } else {
        char kind[64];
        ov_cli_kind(mountdir, crel, kind, sizeof(kind));
        fprintf(out, "%s %s\n", kind, crel);
    }
    free(crel);
    free(full);
    return rc;
}

int brix_overlay_cli_list(const char *mountdir, FILE *out) {
    char *upper = NULL;
    int   rc    = ov_cli_guard(mountdir, &upper);
    if (rc != 0) return rc;
    rc = ov_cli_list_dir(mountdir, upper, "", out);
    free(upper);
    return rc;
}

/* Recursively delete everything inside dirfd (never following symlinks). */
static int ov_cli_reset_contents(int dirfd) {
    int lfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (lfd < 0) return 1;
    DIR *d = fdopendir(lfd);                     /* owns lfd */
    if (d == NULL) { close(lfd); return 1; }

    int            rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (strcmp(n, ".") == 0 || strcmp(n, "..") == 0) continue;
        struct stat st;
        if (fstatat(dirfd, n, &st, AT_SYMLINK_NOFOLLOW) != 0) { rc = 1; break; }
        if (S_ISDIR(st.st_mode)) {
            int sub = openat(dirfd, n, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (sub < 0) { rc = 1; break; }
            rc = ov_cli_reset_contents(sub);
            close(sub);
            if (rc == 0 && unlinkat(dirfd, n, AT_REMOVEDIR) != 0) rc = 1;
        } else if (unlinkat(dirfd, n, 0) != 0) {
            rc = 1;
        }
    }
    closedir(d);
    return rc;
}

int brix_overlay_cli_reset(const char *mountdir) {
    char *upper = NULL;
    int   rc    = ov_cli_guard(mountdir, &upper);
    if (rc != 0) return rc;

    int fd = open(upper, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(upper);
    if (fd < 0) return 1;
    rc = ov_cli_reset_contents(fd);
    close(fd);
    return rc;
}
