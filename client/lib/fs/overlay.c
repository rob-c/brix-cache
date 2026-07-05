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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

        int next = openat(cur, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && mk && errno == ENOENT) {
            mode_t m = mode_fn ? mode_fn(ud, prefix) : 0755;
            if (mkdirat(cur, leaf, m) != 0 && errno != EEXIST) {
                int e = errno;
                close(cur);
                return -e;
            }
            next = openat(cur, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (next < 0) { int e = errno; close(cur); return -e; }
        close(cur);
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

/* Walk `rel` from the upper root and decide how the union sees it: a whiteout
 * on any component, an opaque ancestor, or a non-dir upper component shadowing
 * the remainder all mask the lower layer; a leaf found in upper wins; anything
 * else falls through to lower. */
int brix_overlay_classify(const brix_overlay *ov, const char *rel,
                          struct stat *st, brix_ov_state *state) {
    *state = BRIX_OV_NONE;
    if (rel == NULL) return -EINVAL;

    if (rel[0] == '\0') {                       /* the repo root is upper/ */
        if (st != NULL && fstat(ov->upper_fd, st) != 0) return -errno;
        *state = BRIX_OV_UPPER;
        return 0;
    }

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

        int next = openat(cur, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(cur);
        if (next < 0) return -errno;
        cur = next;
        if (ov_marker_at(cur, BRIX_OV_OPQ_NAME)) opaque = 1;
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
