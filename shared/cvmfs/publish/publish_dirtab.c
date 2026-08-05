/* publish_dirtab.c — .cvmfsdirtab parsing + the nesting pre-pass: split plain
 * directories that now match the dirtab into fresh nested catalogs, dissolve
 * mountpoints that no longer match back into their parent. `.cvmfscatalog`
 * marker files are the per-directory equivalent of a dirtab entry (official
 * grammar): a marker arriving in the changeset nests its directory, a marker
 * whiteout dissolves it, and marker-nested mounts persist without any dirtab
 * rule. Enumeration always reads the PRISTINE orig copies (never the mutating
 * working DBs), so the walk is stable while rows move. Dirs inside
 * mountpoints that keep matching are not rescanned — their layout is already
 * settled. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* strdup/fnmatch under -std=c11 */
#endif
#include "cvmfs/publish/publish_internal.h"

#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DT_XATTR_CAP 65536

/* ---- parsing ------------------------------------------------------------- */

static int dt_bad_pattern(const char *p) {
    if (*p == '!') p++;
    if (*p != '/') return 1;
    for (const char *s = p; (s = strstr(s, "..")) != NULL; s += 2)
        if ((s == p || s[-1] == '/') && (s[2] == '\0' || s[2] == '/'))
            return 1;                    /* ".." path component */
    return 0;
}

static char *dt_trim(char *line) {
    line[strcspn(line, "\r\n")] = '\0';
    char *s = line + strspn(line, " \t");
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) s[--len] = '\0';
    return s;
}

static int dt_append(pub_dirtab_t *dt, const char *s) {
    char **np = realloc(dt->pat, (dt->n + 1) * sizeof(*np));
    if (np == NULL) return -1;
    dt->pat = np;
    char *cp = strdup(s);
    if (cp == NULL) return -1;
    dt->pat[dt->n++] = cp;
    return 0;
}

int pub_dirtab_load(pub_ctx_t *px, const char *path, pub_dirtab_t *dt) {
    memset(dt, 0, sizeof(*dt));
    if (path == NULL) return 0;
    FILE *f = fopen(path, "r");
    if (f == NULL) return 0;             /* absent dirtab = no nesting rules */
    char line[PUB_PATH_MAX], msg[PUB_PATH_MAX];
    int lineno = 0, rc = 0;
    while (rc == 0 && fgets(line, sizeof(line), f) != NULL) {
        lineno++;
        const char *s = dt_trim(line);
        if (s[0] == '\0' || s[0] == '#') continue;
        if (dt_bad_pattern(s)) {
            snprintf(msg, sizeof(msg), "dirtab line %d: unsafe pattern '%s'", lineno, s);
            rc = pub_fail(px, "%s", msg);
        } else if (dt_append(dt, s) != 0) {
            rc = pub_fail(px, "out of memory reading dirtab%s", "");
        }
    }
    fclose(f);
    if (rc != 0) pub_dirtab_free(dt);
    return rc;
}

void pub_dirtab_free(pub_dirtab_t *dt) {
    for (size_t i = 0; i < dt->n; i++) free(dt->pat[i]);
    free(dt->pat);
    for (size_t i = 0; i < dt->n_madd; i++) free(dt->madd[i]);
    free(dt->madd);
    for (size_t i = 0; i < dt->n_mdel; i++) free(dt->mdel[i]);
    free(dt->mdel);
    memset(dt, 0, sizeof(*dt));
}

/* ---- .cvmfscatalog markers ------------------------------------------------ */

static int dt_list_append(char ***v, size_t *n, const char *s, size_t len) {
    char **nv = realloc(*v, (*n + 1) * sizeof(*nv));
    if (nv == NULL) return -1;
    *v = nv;
    char *cp = malloc(len + 1);
    if (cp == NULL) return -1;
    memcpy(cp, s, len);
    cp[len] = '\0';
    nv[(*n)++] = cp;
    return 0;
}

static int dt_in_list(char *const *v, size_t n, const char *p) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(v[i], p) == 0) return 1;
    return 0;
}

int pub_dirtab_markers(pub_ctx_t *px, pub_dirtab_t *dt,
                       const cvmfs_changeset_t *cs) {
    for (size_t i = 0; i < cs->n; i++) {
        const cvmfs_change_t *c = &cs->v[i];
        const char *leaf = strrchr(c->path, '/');
        if (leaf == NULL || strcmp(leaf + 1, ".cvmfscatalog") != 0) continue;
        size_t plen = (size_t) (leaf - c->path);
        if (plen == 0) continue;         /* the root can never be a nested mount */
        int rc = 0;
        if (c->op == CVMFS_CH_ADD_FILE)
            rc = dt_list_append(&dt->madd, &dt->n_madd, c->path, plen);
        else if (c->op == CVMFS_CH_DELETE)
            rc = dt_list_append(&dt->mdel, &dt->n_mdel, c->path, plen);
        if (rc != 0)
            return pub_fail(px, "out of memory collecting markers%s", "");
    }
    return 0;
}

int pub_dirtab_new_nests(const pub_dirtab_t *dt, const char *path) {
    return pub_dirtab_match(dt, path) || dt_in_list(dt->madd, dt->n_madd, path);
}

int pub_dirtab_match(const pub_dirtab_t *dt, const char *path) {
    int matched = 0;
    for (size_t i = 0; i < dt->n; i++) {
        const char *p = dt->pat[i];
        int neg = p[0] == '!';
        if (fnmatch(neg ? p + 1 : p, path, FNM_PATHNAME) == 0)
            matched = !neg;              /* last match wins */
    }
    return matched;
}

/* ---- subtree copy (pristine reader → working catwriter) ------------------ */

typedef struct {
    pub_ctx_t         *px;
    cvmfs_catalog_t   *rd;
    cvmfs_catwriter_t *dst;
    unsigned char     *xbuf;
    const char        *cur_path;     /* entry being copied (chunk callback) */
    int                rc;
} dt_copy_t;

typedef struct {
    cvmfs_dirent_t *v;
    size_t          n, cap;
    int             oom;
} dt_list_t;

static void dt_collect_cb(const cvmfs_dirent_t *e, void *ud) {
    dt_list_t *l = ud;
    if (l->n == l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 16;
        cvmfs_dirent_t *nv = realloc(l->v, ncap * sizeof(*nv));
        if (nv == NULL) {
            l->oom = 1;
            return;
        }
        l->v = nv;
        l->cap = ncap;
    }
    l->v[l->n++] = *e;
}

static void dt_chunk_cb(uint64_t offset, uint64_t size, const cvmfs_hash_t *hash,
                        void *ud) {
    dt_copy_t *cc = ud;
    if (cc->rc == 0
        && cvmfs_catwriter_add_chunk(cc->dst, cc->cur_path, offset, size, hash) != 0)
        cc->rc = -1;
}

static void dt_row_from_dirent(cvmfs_catrow_t *r, const cvmfs_dirent_t *e,
                               const char *path, const unsigned char *xattr,
                               long xlen) {
    memset(r, 0, sizeof(*r));
    r->path = path;
    r->flags = e->flags;
    r->mode = e->mode;
    r->size = e->size;
    r->mtime = e->mtime;
    r->uid = e->uid;
    r->gid = e->gid;
    r->linkcount = e->linkcount;
    r->hardlink_group = e->hardlink_group;
    r->symlink = (e->flags & CVMFS_FLAG_LINK) ? e->symlink : NULL;
    r->hash = e->has_hash ? &e->hash : NULL;
    if (xlen > 0) {
        r->xattr = xattr;
        r->xattr_len = (size_t) xlen;
    }
}

/* Copy every entry strictly UNDER `path` into cc->dst; recurses through plain
 * dirs only (a NESTED_MOUNT row is copied but its content lives elsewhere). */
static int dt_copy_subtree(dt_copy_t *cc, const char *path) {
    dt_list_t l = { NULL, 0, 0, 0 };
    if (cvmfs_catalog_readdir(cc->rd, path, dt_collect_cb, &l) < 0 || l.oom) {
        free(l.v);
        return pub_fail(cc->px, "cannot enumerate %s", path);
    }
    char sub[PUB_PATH_MAX];
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < l.n; i++) {
        const cvmfs_dirent_t *e = &l.v[i];
        if (snprintf(sub, sizeof(sub), "%s/%s", path, e->name) >= (int) sizeof(sub)) {
            rc = pub_fail(cc->px, "path too long under %s", path);
            continue;
        }
        long xlen = cvmfs_catalog_xattr(cc->rd, sub, cc->xbuf, DT_XATTR_CAP);
        cvmfs_catrow_t r;
        dt_row_from_dirent(&r, e, sub, cc->xbuf, xlen);
        if (cvmfs_catwriter_upsert(cc->dst, &r) != 0) {
            rc = pub_fail(cc->px, "cannot copy row %s", sub);
            continue;
        }
        if (e->flags & CVMFS_FLAG_FILE_CHUNK) {
            cc->cur_path = sub;
            if (cvmfs_catalog_chunks(cc->rd, sub, dt_chunk_cb, cc) < 0 || cc->rc != 0)
                rc = pub_fail(cc->px, "cannot copy chunks of %s", sub);
        }
        if (rc == 0 && (e->flags & CVMFS_FLAG_DIR)
            && !(e->flags & CVMFS_FLAG_DIR_NESTED_MOUNT))
            rc = dt_copy_subtree(cc, sub);
    }
    free(l.v);
    return rc;
}

static dt_copy_t *dt_copy_begin(pub_ctx_t *px, const char *orig_db,
                                cvmfs_catwriter_t *dst) {
    dt_copy_t *cc = calloc(1, sizeof(*cc));
    if (cc != NULL) cc->xbuf = malloc(DT_XATTR_CAP);
    if (cc == NULL || cc->xbuf == NULL
        || (cc->rd = cvmfs_catalog_open(orig_db)) == NULL) {
        if (cc != NULL) free(cc->xbuf);
        free(cc);
        pub_fail(px, "cannot open pristine catalog %s", orig_db);
        return NULL;
    }
    cc->px = px;
    cc->dst = dst;
    return cc;
}

static void dt_copy_end(dt_copy_t *cc) {
    cvmfs_catalog_close(cc->rd);
    free(cc->xbuf);
    free(cc);
}

/* ---- nested-row relocation ---------------------------------------------- */

typedef struct {
    pub_ctx_t         *px;
    cvmfs_catwriter_t *dst;
    const char        *prefix;       /* only rows under this ("" = all); */
    size_t             plen;
    int                rc;
} dt_moven_t;

static void dt_moven_cb(const char *path, const char *sha1_hex, uint64_t size,
                        void *ud) {
    dt_moven_t *mv = ud;
    if (mv->rc != 0) return;
    if (mv->plen > 0
        && (strncmp(path, mv->prefix, mv->plen) != 0 || path[mv->plen] != '/'))
        return;
    if (cvmfs_catwriter_set_nested(mv->dst, path, sha1_hex, size) != 0)
        mv->rc = pub_fail(mv->px, "cannot relocate nested row %s", path);
}

static int dt_move_nested(pub_ctx_t *px, cvmfs_catwriter_t *from,
                          cvmfs_catwriter_t *to, const char *prefix) {
    dt_moven_t mv = { px, to, prefix, strlen(prefix), 0 };
    if (cvmfs_catwriter_list_nested(from, dt_moven_cb, &mv) < 0)
        return pub_fail(px, "cannot list nested rows under %s", prefix);
    return mv.rc;
}

/* ---- split / dissolve ---------------------------------------------------- */

static int dt_split(pub_ctx_t *px, pub_cat_t *cat, const char *path,
                    const cvmfs_dirent_t *e, pub_cat_t **out_child) {
    cvmfs_catrow_t row;
    dt_row_from_dirent(&row, e, path, NULL, 0);
    pub_cat_t *child = pub_cat_fresh(px, path, &row);
    if (child == NULL) return -1;
    child->parent = cat;
    dt_copy_t *cc = dt_copy_begin(px, cat->orig_db, child->w);
    if (cc == NULL) return -1;
    int rc = dt_copy_subtree(cc, path);
    dt_copy_end(cc);
    if (rc == 0) rc = dt_move_nested(px, cat->w, child->w, path);
    if (rc == 0 && cvmfs_catwriter_delete_subtree(cat->w, path) < 0)
        rc = pub_fail(px, "cannot detach split subtree %s", path);
    if (rc == 0) {
        row.flags = CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_MOUNT;
        if (cvmfs_catwriter_upsert(cat->w, &row) != 0)
            rc = pub_fail(px, "cannot write mountpoint row %s", path);
    }
    cat->dirty = 1;
    *out_child = child;
    return rc;
}

typedef struct {
    const char  *mount;
    cvmfs_hash_t hash;
    int          found;
} dt_find_t;

static void dt_find_cb(const char *path, const char *sha1_hex, uint64_t size,
                       void *ud) {
    dt_find_t *nf = ud;
    (void) size;
    if (!nf->found && strcmp(path, nf->mount) == 0
        && cvmfs_hash_parse(sha1_hex, strlen(sha1_hex), &nf->hash) == 0)
        nf->found = 1;
}

/* Materialize the nested child behind mountpoint `path` (parent-linked). */
static pub_cat_t *dt_open_child(pub_ctx_t *px, pub_cat_t *cat, const char *path) {
    dt_find_t nf = { path, {0}, 0 };
    if (cvmfs_catwriter_list_nested(cat->w, dt_find_cb, &nf) < 0 || !nf.found) {
        pub_fail(px, "mountpoint %s has no nested_catalogs row", path);
        return NULL;
    }
    pub_cat_t *child = pub_cat_materialize(px, path, &nf.hash);
    if (child != NULL) child->parent = cat;
    return child;
}

/* `child` may be pre-opened by the marker probe; NULL → open it here. */
static int dt_dissolve(pub_ctx_t *px, pub_cat_t *cat, const char *path,
                       pub_cat_t *child) {
    if (child == NULL && (child = dt_open_child(px, cat, path)) == NULL)
        return -1;
    cvmfs_dirent_t root;
    if (cvmfs_catwriter_lookup(child->w, path, &root) != 1)
        return pub_fail(px, "nested catalog %s lacks its root row", path);
    cvmfs_catrow_t r;
    dt_row_from_dirent(&r, &root, path, NULL, 0);
    r.flags = CVMFS_FLAG_DIR;            /* mountpoint becomes a plain dir */
    if (cvmfs_catwriter_upsert(cat->w, &r) != 0)
        return pub_fail(px, "cannot inline mountpoint row %s", path);
    dt_copy_t *cc = dt_copy_begin(px, child->orig_db, cat->w);
    if (cc == NULL) return -1;
    int rc = dt_copy_subtree(cc, path);
    dt_copy_end(cc);
    if (rc == 0) rc = dt_move_nested(px, child->w, cat->w, "");
    if (rc == 0 && cvmfs_catwriter_del_nested(cat->w, path) != 0)
        rc = pub_fail(px, "cannot drop nested row %s", path);
    child->dropped = 1;
    cat->dirty = 1;
    return rc;
}

/* ---- the pre-pass walk --------------------------------------------------- */

/* keep(1) / dissolve(0) / error(-1) for an existing mountpoint. Precedence:
 * a dirtab match or a marker arriving this changeset keeps it; a marker
 * whiteout dissolves it; with no dirtab rules all other mounts persist;
 * otherwise it survives only if the child catalog carries a .cvmfscatalog
 * marker (probing materializes the child, handed back for the dissolve). */
static int dt_mount_stays(pub_ctx_t *px, const pub_dirtab_t *dt, pub_cat_t *cat,
                          const char *path, pub_cat_t **probed) {
    *probed = NULL;
    if (pub_dirtab_match(dt, path)) return 1;
    if (dt_in_list(dt->madd, dt->n_madd, path)) return 1;
    if (dt_in_list(dt->mdel, dt->n_mdel, path)) return 0;
    if (dt->n == 0) return 1;
    pub_cat_t *child = dt_open_child(px, cat, path);
    if (child == NULL) return -1;
    *probed = child;
    char marker[PUB_PATH_MAX];
    if (snprintf(marker, sizeof(marker), "%s/.cvmfscatalog", path)
        >= (int) sizeof(marker))
        return pub_fail(px, "path too long under %s", path);
    cvmfs_dirent_t de;
    int found = cvmfs_catwriter_lookup(child->w, marker, &de);
    if (found < 0)
        return pub_fail(px, "cannot probe marker under %s", path);
    return found == 1 && (de.flags & CVMFS_FLAG_FILE) ? 1 : 0;
}

static int dt_walk(pub_ctx_t *px, const pub_dirtab_t *dt, pub_cat_t *cat,
                   cvmfs_catalog_t *rd, const char *path) {
    dt_list_t l = { NULL, 0, 0, 0 };
    if (cvmfs_catalog_readdir(rd, path, dt_collect_cb, &l) < 0 || l.oom) {
        free(l.v);
        return pub_fail(px, "cannot walk %s", path[0] ? path : "(root)");
    }
    char sub[PUB_PATH_MAX];
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < l.n; i++) {
        const cvmfs_dirent_t *e = &l.v[i];
        if (!(e->flags & CVMFS_FLAG_DIR)) continue;
        if (snprintf(sub, sizeof(sub), "%s/%s", path, e->name) >= (int) sizeof(sub)) {
            rc = pub_fail(px, "path too long under %s", path);
            continue;
        }
        if (e->flags & CVMFS_FLAG_DIR_NESTED_MOUNT) {
            pub_cat_t *probed = NULL;
            int stay = dt_mount_stays(px, dt, cat, sub, &probed);
            if (stay < 0) rc = -1;
            else if (stay == 0) rc = dt_dissolve(px, cat, sub, probed);
            continue;                    /* surviving mounts stay as they are */
        }
        pub_cat_t *owner = cat;
        if (pub_dirtab_new_nests(dt, sub)) rc = dt_split(px, cat, sub, e, &owner);
        if (rc == 0) rc = dt_walk(px, dt, owner, rd, sub);
    }
    free(l.v);
    return rc;
}

int pub_dirtab_apply(pub_ctx_t *px, const pub_dirtab_t *dt) {
    if (dt->n == 0 && dt->n_madd == 0 && dt->n_mdel == 0) return 0;
    pub_cat_t *root = px->cats;
    cvmfs_catalog_t *rd = cvmfs_catalog_open(root->orig_db);
    if (rd == NULL)
        return pub_fail(px, "cannot open pristine root catalog%s", "");
    int rc = dt_walk(px, dt, root, rd, "");
    cvmfs_catalog_close(rd);
    return rc;
}
