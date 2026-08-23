/* fsck.c — reader-only repository integrity check (phase-96 S8).
 *
 * WHAT: walk every catalog reachable from .cvmfspublished, recompute the
 *       self_* counter family from the actual row set (the same definitions
 *       cvmfs_catwriter_update_counters uses) and the subtree_* family from
 *       the children's totals, and flag any drift, malformed xattr BLOB or
 *       unreachable nested catalog.
 * WHY:  counters steer client cache sizing and replication; silent drift is a
 *       publish bug — fsck is the oracle the S8 tests tamper against.
 * HOW:  catalogs are fetched from CAS (identity-verified + inflated by
 *       pub_fetch_catalog) into a throwaway workdir and opened READ-ONLY via
 *       the catalog reader; nothing in the repository is ever written. A
 *       nested_catalogs row without a matching mountpoint row cannot be
 *       enumerated by the reader API, but the resulting self_nested count
 *       drift is still caught. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* mkdir/unlink & friends under -std=c11 */
#endif
#include "cvmfs/publish/publish_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {                                   /* indices match pub_counter_names */
    FK_REGULAR, FK_CHUNKED, FK_CHUNKS, FK_DIR, FK_SYMLINK,
    FK_NESTED, FK_FILE_SIZE, FK_CHUNKED_SIZE, FK_XATTR,
};

typedef struct {                         /* slim dirent: what tallying needs */
    char         name[256];
    uint32_t     flags;
    uint64_t     size;
    int          has_hash;
    cvmfs_hash_t hash;                   /* content hash of a regular file */
} fk_ent_t;

typedef struct {
    pub_ctx_t *px;
    int        data;                     /* also CAS-verify payload objects */
} fk_ctx_t;

typedef struct {
    fk_ent_t *v;
    size_t    n, cap;
    int       bad;
} fk_list_t;

static void fk_collect_cb(const cvmfs_dirent_t *e, void *ud) {
    fk_list_t *l = ud;
    if (l->bad) return;
    if (l->n == l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 16;
        fk_ent_t *nv = realloc(l->v, ncap * sizeof(*nv));
        if (nv == NULL) {
            l->bad = 1;
            return;
        }
        l->v = nv;
        l->cap = ncap;
    }
    snprintf(l->v[l->n].name, sizeof(l->v[l->n].name), "%s", e->name);
    l->v[l->n].flags = e->flags;
    l->v[l->n].size = e->size;
    l->v[l->n].has_hash = e->has_hash;
    l->v[l->n].hash = e->hash;
    l->n++;
}

typedef struct {
    char  **v;
    size_t  n, cap;
} fk_paths_t;

static int fk_paths_add(fk_paths_t *p, const char *path) {
    if (p->n == p->cap) {
        size_t ncap = p->cap ? p->cap * 2 : 8;
        char **nv = realloc(p->v, ncap * sizeof(*nv));
        if (nv == NULL) return -1;
        p->v = nv;
        p->cap = ncap;
    }
    p->v[p->n] = strdup(path);
    if (p->v[p->n] == NULL) return -1;
    p->n++;
    return 0;
}

static void fk_paths_free(fk_paths_t *p) {
    for (size_t i = 0; i < p->n; i++) free(p->v[i]);
    free(p->v);
    memset(p, 0, sizeof(*p));
}

typedef struct {                         /* chunk walk: count, optionally verify */
    fk_ctx_t   *fk;
    const char *path;
    int         rc;
} fk_chunks_t;

static void fk_chunk_cb(uint64_t off, uint64_t size, const cvmfs_hash_t *h,
                        void *ud) {
    fk_chunks_t *c = ud;
    (void) off; (void) size;
    if (c->fk->data && c->rc == 0)
        c->rc = pub_verify_object(c->fk->px, h, 'P', c->path);
}

/* xattr presence + well-formedness of one row (own stack frame: the 64 KiB
 * buffer is never live across the directory recursion). */
static int fk_xattr_check(pub_ctx_t *px, cvmfs_catalog_t *rd, const char *path,
                          int64_t self[]) {
    unsigned char buf[65536];
    long xl = cvmfs_catalog_xattr(rd, path, buf, sizeof(buf));
    if (xl < 0)
        return pub_fail(px, "cannot read xattrs of %s", path[0] ? path : "(root)");
    if (xl == 0) return 0;
    int n = cvmfs_xattr_count(buf, (size_t) xl);
    for (int i = 0; i < n; i++) {        /* every entry must decode in bounds */
        const char *key;
        const unsigned char *val;
        size_t klen, vlen;
        if (cvmfs_xattr_unpack(buf, (size_t) xl, (size_t) i,
                               &key, &klen, &val, &vlen) != 0)
            n = -1;
    }
    if (n < 0) return pub_fail(px, "malformed xattr BLOB on %s", path);
    self[FK_XATTR]++;
    return 0;
}

static int fk_tally(fk_ctx_t *fk, cvmfs_catalog_t *rd, const char *path,
                    const fk_ent_t *e, int64_t self[]) {
    if (e->flags & CVMFS_FLAG_LINK) {
        self[FK_SYMLINK]++;
    } else if (e->flags & CVMFS_FLAG_FILE_CHUNK) {
        self[FK_CHUNKED]++;
        self[FK_CHUNKED_SIZE] += (int64_t) e->size;
        fk_chunks_t c = { fk, path, 0 };
        int n = cvmfs_catalog_chunks(rd, path, fk_chunk_cb, &c);
        if (n < 0) return pub_fail(fk->px, "cannot enumerate chunks of %s", path);
        if (c.rc != 0) return -1;
        self[FK_CHUNKS] += n;
    } else if (e->flags & CVMFS_FLAG_FILE) {
        self[FK_REGULAR]++;
        self[FK_FILE_SIZE] += (int64_t) e->size;
        if (fk->data && e->has_hash
            && pub_verify_object(fk->px, &e->hash, 0, path) != 0)
            return -1;
    } else if (e->flags & CVMFS_FLAG_DIR) {
        self[FK_DIR]++;
    }
    return fk_xattr_check(fk->px, rd, path, self);
}

static int fk_walk(fk_ctx_t *fk, cvmfs_catalog_t *rd, const char *dir,
                   int64_t self[], fk_paths_t *mounts) {
    fk_list_t l = { NULL, 0, 0, 0 };
    if (cvmfs_catalog_readdir(rd, dir, fk_collect_cb, &l) < 0 || l.bad) {
        free(l.v);
        return pub_fail(fk->px, "cannot read directory %s",
                        dir[0] ? dir : "(root)");
    }
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < l.n; i++) {
        if (l.v[i].name[0] == '\0')
            continue;        /* root row of "" in legacy self-parented catalogs */
        char sub[PUB_PATH_MAX];
        snprintf(sub, sizeof(sub), "%s/%s", dir, l.v[i].name);
        rc = fk_tally(fk, rd, sub, &l.v[i], self);
        if (rc != 0) break;
        if (l.v[i].flags & CVMFS_FLAG_DIR_NESTED_MOUNT) {
            if (fk_paths_add(mounts, sub) != 0)
                rc = pub_fail(fk->px, "out of memory collecting mountpoints%s", "");
        } else if (l.v[i].flags & CVMFS_FLAG_DIR) {
            rc = fk_walk(fk, rd, sub, self, mounts);
        }
    }
    free(l.v);
    return rc;
}

/* Stored counters of `family` vs the recomputed values; absent rows read 0. */
static int fk_compare(pub_ctx_t *px, cvmfs_catalog_t *rd, const char *mount,
                      const char *family, const int64_t computed[]) {
    for (int i = 0; i < PUB_NCOUNTERS; i++) {
        char name[48];
        int64_t stored = 0;
        snprintf(name, sizeof(name), "%s_%s", family, pub_counter_names[i]);
        if (cvmfs_catalog_counter(rd, name, &stored) < 0)
            return pub_fail(px, "cannot read counter %s", name);
        if (stored != computed[i]) {
            char msg[PUB_PATH_MAX + 128];
            snprintf(msg, sizeof(msg),
                     "counter drift in catalog %s: %s stored %lld computed %lld",
                     mount[0] ? mount : "(root)", name,
                     (long long) stored, (long long) computed[i]);
            return pub_fail(px, "%s", msg);
        }
    }
    return 0;
}

/*
 * WHAT: Fetch a catalog object into a temporary SQLite file and open it.
 * WHY:  Recursive fsck needs a uniform owned handle for each catalog hash.
 * HOW:  Verify-fetch plaintext, write the work file, and report open failures.
 */
static cvmfs_catalog_t *fk_open_catalog(fk_ctx_t *fk, const char *mount,
                                        const cvmfs_hash_t *hash,
                                        char *tmp, size_t tmp_len) {
    pub_ctx_t    *px = fk->px;
    size_t        plain_len = 0;
    unsigned char *plain = pub_fetch_catalog(px, hash, &plain_len);
    cvmfs_catalog_t *catalog;

    if (plain == NULL)
        return NULL;
    snprintf(tmp, tmp_len, "%s/fsck.%d.db", px->workdir, px->seq++);
    catalog = pub_spit(tmp, plain, plain_len, 0) == 0 ?
              cvmfs_catalog_open(tmp) : NULL;
    free(plain);
    if (catalog != NULL)
        return catalog;
    unlink(tmp);
    pub_fail(px, "cannot open catalog for %s", mount[0] ? mount : "(root)");
    return NULL;
}

/*
 * WHAT: Recompute and validate one catalog's own counters and mountpoint list.
 * WHY:  Child catalog recursion must start only after the parent is internally sound.
 * HOW:  Check its root row and xattrs, walk entries, then compare self counters.
 */
static int fk_check_self(fk_ctx_t *fk, cvmfs_catalog_t *catalog,
                         const char *mount, int64_t self[],
                         fk_paths_t *mounts) {
    cvmfs_dirent_t root;
    int            rc = 0;

    if (cvmfs_catalog_lookup(catalog, mount, &root) != 1)
        rc = pub_fail(fk->px, "catalog root row missing for %s",
                      mount[0] ? mount : "(root)");
    if (rc == 0 && mount[0] != '\0')
        self[FK_DIR]++;
    if (rc == 0)
        rc = fk_xattr_check(fk->px, catalog, mount, self);
    if (rc == 0)
        rc = fk_walk(fk, catalog, mount, self, mounts);
    if (rc != 0)
        return rc;
    self[FK_NESTED] = (int64_t) mounts->n;
    return fk_compare(fk->px, catalog, mount, "self", self);
}

static int fk_check(fk_ctx_t *fk, const char *mount,
                    const cvmfs_hash_t *hash, int64_t total[]);

/*
 * WHAT: Validate every nested catalog and accumulate its subtree counters.
 * WHY:  Parent subtree metadata must equal the recursively verified children.
 * HOW:  Resolve each mount hash, recurse, and add the returned counter vector.
 */
static int fk_check_children(fk_ctx_t *fk, cvmfs_catalog_t *catalog,
                             const fk_paths_t *mounts, int64_t subtree[]) {
    for (size_t i = 0; i < mounts->n; i++) {
        cvmfs_hash_t child_hash;
        uint64_t     child_size = 0;
        int64_t      child_total[PUB_NCOUNTERS];
        int           rc;

        if (cvmfs_catalog_nested(catalog, mounts->v[i], &child_hash,
                                 &child_size) != 1)
            return pub_fail(fk->px, "mountpoint %s has no nested_catalogs row",
                            mounts->v[i]);
        rc = fk_check(fk, mounts->v[i], &child_hash, child_total);
        if (rc != 0)
            return rc;
        for (int counter = 0; counter < PUB_NCOUNTERS; counter++)
            subtree[counter] += child_total[counter];
    }
    return 0;
}

/* Verify the catalog `hash` mounted at `mount`, recursing into its nested
 * children; on success tot[] gets its self+subtree totals. */
static int fk_check(fk_ctx_t *fk, const char *mount, const cvmfs_hash_t *hash,
                    int64_t tot[]) {
    pub_ctx_t      *px = fk->px;
    char            tmp[PUB_PATH_MAX + 32] = {0};
    cvmfs_catalog_t *rd = fk_open_catalog(fk, mount, hash, tmp, sizeof(tmp));
    int64_t self[PUB_NCOUNTERS] = { 0 }, subtree[PUB_NCOUNTERS] = { 0 };
    fk_paths_t mounts = { NULL, 0, 0 };
    int        rc;

    if (rd == NULL)
        return -1;
    rc = fk_check_self(fk, rd, mount, self, &mounts);
    if (rc == 0)
        rc = fk_check_children(fk, rd, &mounts, subtree);
    if (rc == 0)
        rc = fk_compare(px, rd, mount, "subtree", subtree);
    for (int counter = 0; rc == 0 && counter < PUB_NCOUNTERS; counter++)
        tot[counter] = self[counter] + subtree[counter];
    fk_paths_free(&mounts);
    cvmfs_catalog_close(rd);
    unlink(tmp);
    return rc;
}

int cvmfs_fsck_run(const char *repo_dir, int check_data, char *err, size_t errlen) {
    cvmfs_publish_opts_t opts;
    pub_ctx_t px;
    memset(&opts, 0, sizeof(opts));
    memset(&px, 0, sizeof(px));
    opts.repo_dir = repo_dir;
    px.o = &opts;
    px.err = err;
    px.errlen = errlen;
    snprintf(px.workdir, sizeof(px.workdir), "%s/.brix.fsck.tmp", repo_dir);
    if (mkdir(px.workdir, 0755) != 0 && errno != EEXIST)
        return pub_fail(&px, "cannot create %s", px.workdir);
    char path[PUB_PATH_MAX];
    size_t mlen = 0;
    snprintf(path, sizeof(path), "%s/.cvmfspublished", repo_dir);
    unsigned char *manbuf = pub_slurp(path, &mlen);
    cvmfs_manifest_t man;
    int rc = manbuf != NULL && cvmfs_manifest_parse(manbuf, mlen, &man) == 0
          ? 0 : pub_fail(&px, "cannot parse %s", path);
    fk_ctx_t fk = { &px, check_data };
    if (rc == 0 && check_data)
        rc = pub_verify_object(&px, &man.certificate, 'X', ".cvmfspublished");
    int64_t tot[PUB_NCOUNTERS];
    if (rc == 0) rc = fk_check(&fk, "", &man.root_catalog, tot);
    free(manbuf);
    rmdir(px.workdir);
    return rc;
}
