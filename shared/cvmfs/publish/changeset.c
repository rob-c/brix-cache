/* changeset.c — upper-tree → publish changeset. See changeset.h. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* *at() + fdopendir under -std=c11 */
#endif
#include "cvmfs/publish/changeset.h"
#include "cvmfs/catalog/catalog_write.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define CH_WH_PREFIX  ".brix.wh."
#define CH_OPQ_NAME   ".brix.opq"
#define CH_TMP_PREFIX ".brix.tmp."
#define CH_PATH_MAX   1024
#define CH_XATTR_CAP  65536              /* packed-BLOB bound (catalog sanity) */
#define CH_XATTR_MAX  255                /* entries per row (pack format bound) */

typedef struct {
    cvmfs_changeset_t *cs;
    const char        *upper_root;      /* absolute, for src paths */
    char              *err;
    size_t             errlen;
} ch_scan_t;

static int ch_fail(const ch_scan_t *sc, const char *fmt, const char *arg) {
    if (sc->err != NULL && sc->errlen > 0)
        snprintf(sc->err, sc->errlen, fmt, arg);
    return -1;
}

static cvmfs_change_t *ch_new(cvmfs_changeset_t *cs) {
    if (cs->n == cs->cap) {
        size_t ncap = cs->cap ? cs->cap * 2 : 64;
        cvmfs_change_t *nv = realloc(cs->v, ncap * sizeof(*nv));
        if (nv == NULL) return NULL;
        cs->v = nv;
        cs->cap = ncap;
    }
    cvmfs_change_t *c = &cs->v[cs->n++];
    memset(c, 0, sizeof(*c));
    return c;
}

static char *ch_join(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    char *s = malloc(la + lb + 2);
    if (s != NULL) snprintf(s, la + lb + 2, "%s/%s", a, b);
    return s;
}

static int ch_add(ch_scan_t *sc, int op, const char *rel, const char *name,
                  const struct stat *st, const char *link_target) {
    cvmfs_change_t *c = ch_new(sc->cs);
    if (c == NULL) return ch_fail(sc, "out of memory near %s", rel);
    c->op = op;
    c->path = ch_join(rel, name);
    if (op == CVMFS_CH_ADD_FILE) c->src = ch_join(sc->upper_root, c->path + 1);
    if (op == CVMFS_CH_ADD_LINK && link_target != NULL) c->link = strdup(link_target);
    if (st != NULL) {
        c->mode = st->st_mode;
        c->uid = (uint32_t) st->st_uid;
        c->gid = (uint32_t) st->st_gid;
        c->mtime = st->st_mtime;
        c->size = (uint64_t) st->st_size;
    }
    if (c->path == NULL
        || (op == CVMFS_CH_ADD_FILE && c->src == NULL)
        || (op == CVMFS_CH_ADD_LINK && c->link == NULL))
        return ch_fail(sc, "out of memory near %s", rel);
    return 0;
}

/* ---- xattr capture (packed user.* BLOB per file/dir) ---------------------- */

/* Append the readable user.* keys of `fd` to keys/vals/lens; *out_n is kept
 * current so the caller can free vals[0..*out_n) on every path. */
static int ch_xattr_collect(ch_scan_t *sc, int fd, const char *name,
                            const char *list, ssize_t lsz, const char *keys[],
                            unsigned char *vals[], size_t lens[], size_t *out_n) {
    unsigned char tmp[65536];
    for (const char *k = list; k < list + lsz; k += strlen(k) + 1) {
        if (strncmp(k, "user.", 5) != 0) continue;
        if (*out_n == CH_XATTR_MAX)
            return ch_fail(sc, "oversized xattr set on %s", name);
        ssize_t vsz = fgetxattr(fd, k, tmp, sizeof(tmp));
        if (vsz < 0 || vsz > 65535)
            return ch_fail(sc, "oversized or unreadable xattr on %s", name);
        unsigned char *v = malloc(vsz > 0 ? (size_t) vsz : 1);
        if (v == NULL)
            return ch_fail(sc, "out of memory near %s", name);
        memcpy(v, tmp, (size_t) vsz);
        keys[*out_n] = k;
        vals[*out_n] = v;
        lens[*out_n] = (size_t) vsz;
        (*out_n)++;
    }
    return 0;
}

/* Capture the user.* xattrs behind `fd` as a packed BLOB (NULL when none).
 * A set exceeding the catalog BLOB bounds fails the scan — fail closed, never
 * silently drop attributes. */
static int ch_xattr_capture(ch_scan_t *sc, int fd, const char *name,
                            unsigned char **out, size_t *outlen) {
    *out = NULL;
    *outlen = 0;
    ssize_t lsz = flistxattr(fd, NULL, 0);
    if (lsz <= 0) return 0;              /* none, or FS without xattr support */
    char *list = malloc((size_t) lsz);
    if (list == NULL || (lsz = flistxattr(fd, list, (size_t) lsz)) < 0) {
        free(list);
        return ch_fail(sc, "cannot list xattrs of %s", name);
    }
    const char    *keys[CH_XATTR_MAX];
    unsigned char *vals[CH_XATTR_MAX];
    size_t         lens[CH_XATTR_MAX], n = 0;
    int rc = ch_xattr_collect(sc, fd, name, list, lsz, keys, vals, lens, &n);
    if (rc == 0 && n > 0) {
        unsigned char *blob = malloc(CH_XATTR_CAP);
        int plen = blob != NULL
            ? cvmfs_xattr_pack(keys, (const unsigned char *const *) vals, lens,
                               n, blob, CH_XATTR_CAP)
            : -1;
        if (plen > 0) {
            *out = blob;
            *outlen = (size_t) plen;
        } else {
            free(blob);
            rc = ch_fail(sc, "oversized xattr set on %s", name);
        }
    }
    for (size_t i = 0; i < n; i++) free(vals[i]);
    free(list);
    return rc;
}

/* Record one directory entry; recurse into real subdirectories. `rel` is the
 * repo-relative parent ("" at the upper root); `dirfd` its O_NOFOLLOW handle. */
static int ch_entry(ch_scan_t *sc, int dirfd, const char *rel, const char *name);

static int ch_scan_dir(ch_scan_t *sc, int dirfd, const char *rel) {
    int dup_fd = dup(dirfd);            /* fdopendir consumes its fd */
    DIR *d = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
    if (d == NULL) {
        if (dup_fd >= 0) close(dup_fd);
        return ch_fail(sc, "cannot list upper dir %s", rel);
    }
    rewinddir(d);
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0
            || strcmp(e->d_name, CH_OPQ_NAME) == 0
            || strncmp(e->d_name, CH_TMP_PREFIX, sizeof(CH_TMP_PREFIX) - 1) == 0)
            continue;
        rc = ch_entry(sc, dirfd, rel, e->d_name);
    }
    closedir(d);
    return rc;
}

/* Regular file: record the add plus its hardlink identity and xattrs. The
 * O_NOFOLLOW fd pins the object the xattrs are read from. */
static int ch_entry_file(ch_scan_t *sc, int dirfd, const char *rel,
                         const char *name, const struct stat *st) {
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return ch_fail(sc, "cannot open upper file %s", name);
    int rc = ch_add(sc, CVMFS_CH_ADD_FILE, rel, name, st, NULL);
    if (rc == 0) {
        cvmfs_change_t *c = &sc->cs->v[sc->cs->n - 1];
        c->dev = (uint64_t) st->st_dev;
        c->ino = (uint64_t) st->st_ino;
        c->nlink = (uint32_t) st->st_nlink;
        rc = ch_xattr_capture(sc, fd, name, &c->xattr, &c->xattr_len);
    }
    close(fd);
    return rc;
}

static int ch_entry(ch_scan_t *sc, int dirfd, const char *rel, const char *name) {
    if (strlen(rel) + strlen(name) + 2 > CH_PATH_MAX)
        return ch_fail(sc, "upper path too long under %s", rel);
    if (strncmp(name, CH_WH_PREFIX, sizeof(CH_WH_PREFIX) - 1) == 0) {
        const char *victim = name + sizeof(CH_WH_PREFIX) - 1;
        if (victim[0] == '\0' || strcmp(victim, ".") == 0 || strcmp(victim, "..") == 0)
            return ch_fail(sc, "malformed whiteout name in %s", rel);
        return ch_add(sc, CVMFS_CH_DELETE, rel, victim, NULL, NULL);
    }

    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return ch_fail(sc, "cannot stat upper entry %s", name);

    if (S_ISLNK(st.st_mode)) {
        char target[CH_PATH_MAX];
        ssize_t n = readlinkat(dirfd, name, target, sizeof(target) - 1);
        if (n < 0 || (size_t) n >= sizeof(target) - 1)
            return ch_fail(sc, "unreadable symlink %s", name);
        target[n] = '\0';
        return ch_add(sc, CVMFS_CH_ADD_LINK, rel, name, &st, target);
    }
    if (S_ISREG(st.st_mode))
        return ch_entry_file(sc, dirfd, rel, name, &st);
    if (!S_ISDIR(st.st_mode))
        return ch_fail(sc, "unsupported upper entry type: %s", name);

    /* directory: O_NOFOLLOW descent — a symlink can never be traversed */
    int sub = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sub < 0)
        return ch_fail(sc, "cannot open upper dir %s", name);
    char subrel[CH_PATH_MAX];
    snprintf(subrel, sizeof(subrel), "%s/%s", rel, name);

    cvmfs_change_t *c;
    int rc = ch_add(sc, CVMFS_CH_ADD_DIR, rel, name, &st, NULL);
    if (rc == 0) {
        c = &sc->cs->v[sc->cs->n - 1];
        c->opaque = faccessat(sub, CH_OPQ_NAME, F_OK, AT_SYMLINK_NOFOLLOW) == 0;
        rc = ch_xattr_capture(sc, sub, name, &c->xattr, &c->xattr_len);
    }
    if (rc == 0) rc = ch_scan_dir(sc, sub, subrel);
    close(sub);
    return rc;
}

/* DELETEs first, then ADDs by path — parents strictly before children. */
static int ch_cmp(const void *pa, const void *pb) {
    const cvmfs_change_t *a = pa, *b = pb;
    int da = a->op == CVMFS_CH_DELETE, db = b->op == CVMFS_CH_DELETE;
    if (da != db) return db - da;
    return strcmp(a->path, b->path);
}

/* ---- hardlink grouping ---------------------------------------------------- */

typedef struct {
    uint64_t dev, ino;
    size_t   idx;
} ch_hl_t;

static int ch_hl_cmp(const void *pa, const void *pb) {
    const ch_hl_t *a = pa, *b = pb;
    if (a->dev != b->dev) return a->dev < b->dev ? -1 : 1;
    if (a->ino != b->ino) return a->ino < b->ino ? -1 : 1;
    return a->idx < b->idx ? -1 : a->idx > b->idx;
}

/* Files sharing an inode within the upper tree form a hardlink group: common
 * nonzero group id, linkcount = member count found by the scan (links held
 * outside the published tree do not count — the catalog can only describe
 * what it contains). */
static int ch_hardlink_groups(cvmfs_changeset_t *cs) {
    size_t nf = 0;
    for (size_t i = 0; i < cs->n; i++)
        if (cs->v[i].op == CVMFS_CH_ADD_FILE && cs->v[i].nlink > 1) nf++;
    if (nf < 2) return 0;
    ch_hl_t *hl = malloc(nf * sizeof(*hl));
    if (hl == NULL) return -1;
    size_t m = 0;
    for (size_t i = 0; i < cs->n; i++)
        if (cs->v[i].op == CVMFS_CH_ADD_FILE && cs->v[i].nlink > 1)
            hl[m++] = (ch_hl_t) { cs->v[i].dev, cs->v[i].ino, i };
    qsort(hl, nf, sizeof(*hl), ch_hl_cmp);
    uint32_t group = 0;
    for (size_t s = 0; s < nf;) {
        size_t e = s + 1;
        while (e < nf && hl[e].dev == hl[s].dev && hl[e].ino == hl[s].ino) e++;
        if (e - s >= 2) {
            group++;
            for (size_t j = s; j < e; j++) {
                cs->v[hl[j].idx].hardlink_group = group;
                cs->v[hl[j].idx].linkcount = (uint32_t) (e - s);
            }
        }
        s = e;
    }
    free(hl);
    return 0;
}

int cvmfs_changeset_scan(const char *upper_dir, cvmfs_changeset_t *cs,
                         char *err, size_t errlen) {
    memset(cs, 0, sizeof(*cs));
    ch_scan_t sc = { cs, upper_dir, err, errlen };
    int root = open(upper_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0)
        return ch_fail(&sc, "cannot open upper tree %s", upper_dir);
    int rc = ch_scan_dir(&sc, root, "");
    close(root);
    if (rc != 0) {
        cvmfs_changeset_free(cs);
        return -1;
    }
    qsort(cs->v, cs->n, sizeof(*cs->v), ch_cmp);
    if (ch_hardlink_groups(cs) != 0) {
        cvmfs_changeset_free(cs);
        return ch_fail(&sc, "out of memory grouping hardlinks%s", "");
    }
    return 0;
}

/* ---- prefix remap (phase-104 D8/D9) --------------------------------------- */

/* One prefix component: non-empty, not "."/"..", not the reserved marker
 * grammar (every marker spells ".brix.*"). */
static int ch_prefix_component_ok(const char *s, size_t n) {
    if (n == 0) return 0;
    if (n <= 2 && strncmp(s, "..", n) == 0) return 0;
    if (n >= 6 && strncmp(s, ".brix.", 6) == 0) return 0;
    return 1;
}

static int ch_prefix_validate(ch_scan_t *sc, const char *prefix, size_t plen) {
    for (const char *s = prefix + 1; s < prefix + plen; ) {
        const char *e = memchr(s, '/', (size_t) (prefix + plen - s));
        if (e == NULL) e = prefix + plen;
        if (!ch_prefix_component_ok(s, (size_t) (e - s)))
            return ch_fail(sc, "invalid prefix component in %s", prefix);
        s = e + 1;
    }
    return 0;
}

int cvmfs_changeset_reprefix(cvmfs_changeset_t *cs, const char *prefix,
                             char *err, size_t errlen) {
    ch_scan_t sc = { cs, NULL, err, errlen };
    if (prefix == NULL || prefix[0] != '/')
        return ch_fail(&sc, "prefix must be absolute: %s",
                       prefix != NULL ? prefix : "(null)");
    size_t plen = strlen(prefix);
    while (plen > 1 && prefix[plen - 1] == '/') plen--;
    if (plen >= CH_PATH_MAX)
        return ch_fail(&sc, "prefix too long: %s", prefix);
    if (plen == 1) return 0;                 /* "/" — already rooted */
    if (ch_prefix_validate(&sc, prefix, plen) != 0)
        return -1;

    for (size_t i = 0; i < cs->n; i++) {
        cvmfs_change_t *c = &cs->v[i];
        size_t l = strlen(c->path);
        if (plen + l >= CH_PATH_MAX)
            return ch_fail(&sc, "reprefixed path too long: %s", c->path);
        char *np = malloc(plen + l + 1);
        if (np == NULL)
            return ch_fail(&sc, "out of memory near %s", c->path);
        memcpy(np, prefix, plen);
        memcpy(np + plen, c->path, l + 1);
        free(c->path);
        c->path = np;
    }

    /* the ancestor chain, "/a", "/a/b", …, prefix itself — upserts that a
     * published non-dir fails (no_clobber), so a foreign file is never
     * silently retyped into a directory */
    int64_t now = (int64_t) time(NULL);
    for (size_t p = 1; p <= plen; p++) {
        if (p != plen && prefix[p] != '/') continue;
        cvmfs_change_t *c = ch_new(cs);
        char *ancestor = c != NULL ? strndup(prefix, p) : NULL;
        if (ancestor == NULL)
            return ch_fail(&sc, "out of memory near %s", prefix);
        c->op = CVMFS_CH_ADD_DIR;
        c->path = ancestor;
        c->mode = S_IFDIR | 0755;
        c->uid = (uint32_t) getuid();
        c->gid = (uint32_t) getgid();
        c->mtime = now;
        c->no_clobber = 1;
    }
    qsort(cs->v, cs->n, sizeof(*cs->v), ch_cmp);
    return 0;
}

void cvmfs_changeset_free(cvmfs_changeset_t *cs) {
    for (size_t i = 0; i < cs->n; i++) {
        free(cs->v[i].path);
        free(cs->v[i].src);
        free(cs->v[i].link);
        free(cs->v[i].xattr);
    }
    free(cs->v);
    memset(cs, 0, sizeof(*cs));
}
