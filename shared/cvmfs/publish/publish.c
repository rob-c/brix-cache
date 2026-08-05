/* publish.c — the publish engine: changeset → new signed revision.
 * See publish.h; catalog tree plumbing shared with publish_dirtab.c via
 * publish_internal.h. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* fsync/getpid & friends under -std=c11 */
#endif
#include "cvmfs/publish/publish_internal.h"
#include "cvmfs/object/object.h"
#include "cvmfs/reflog/reflog.h"
#include "cvmfs/signature/sign.h"
#include "cvmfs/signature/verify.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int pub_fail(pub_ctx_t *px, const char *fmt, const char *arg) {
    if (px->err != NULL && px->errlen > 0)
        snprintf(px->err, px->errlen, fmt, arg);
    return -1;
}

/* ---- file helpers -------------------------------------------------------- */

unsigned char *pub_slurp(const char *path, size_t *len) {
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) != 0) {
        if (fd >= 0) close(fd);
        return NULL;
    }
    unsigned char *buf = malloc(st.st_size > 0 ? (size_t) st.st_size : 1);
    ssize_t n = buf != NULL ? read(fd, buf, (size_t) st.st_size) : -1;
    close(fd);
    if (n != st.st_size) {
        free(buf);
        return NULL;
    }
    *len = (size_t) st.st_size;
    return buf;
}

int pub_spit(const char *path, const unsigned char *buf, size_t len, int do_sync) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, buf, len);
    int rc = n == (ssize_t) len && (!do_sync || fsync(fd) == 0) ? 0 : -1;
    return close(fd) == 0 ? rc : -1;
}

/* ---- catalog tree -------------------------------------------------------- */

static pub_cat_t *pub_cat_register(pub_ctx_t *px, const char *mount) {
    pub_cat_t *c = calloc(1, sizeof(*c));
    if (c == NULL) return NULL;
    snprintf(c->mount, sizeof(c->mount), "%s", mount);
    snprintf(c->db, sizeof(c->db), "%s/cat.%d.db", px->workdir, px->seq++);
    /* root first, everything else appended (root stays list head) */
    if (px->cats == NULL) {
        px->cats = c;
    } else {
        pub_cat_t *t = px->cats;
        while (t->next != NULL) t = t->next;
        t->next = c;
    }
    return c;
}

/* CAS location of `hash`: <repo>/data/<first two hex>/<rest><suffix>. */
static void pub_object_path(pub_ctx_t *px, const cvmfs_hash_t *hash, char suffix,
                            char *hex, size_t hexlen, char *obj, size_t objlen) {
    cvmfs_hash_to_hex(hash, suffix, hex, hexlen);
    snprintf(obj, objlen, "%s/data/%.2s/%s", px->o->repo_dir, hex, hex + 2);
}

int pub_verify_object(pub_ctx_t *px, const cvmfs_hash_t *hash, char suffix,
                      const char *what) {
    char hex[64], obj[PUB_PATH_MAX], msg[PUB_PATH_MAX + 128];
    pub_object_path(px, hash, suffix, hex, sizeof(hex), obj, sizeof(obj));
    size_t slen = 0;
    unsigned char *stored = pub_slurp(obj, &slen);
    if (stored == NULL) {
        snprintf(msg, sizeof(msg), "object %s of %s missing", hex, what);
        return pub_fail(px, "%s", msg);
    }
    cvmfs_hash_t got;
    int ok = cvmfs_object_hash(CVMFS_HASH_SHA1, stored, slen, &got) == 0
             && cvmfs_hash_eq(&got, hash);
    free(stored);
    if (ok) return 0;
    snprintf(msg, sizeof(msg), "object %s of %s fails CAS verification", hex, what);
    return pub_fail(px, "%s", msg);
}

unsigned char *pub_fetch_object(pub_ctx_t *px, const cvmfs_hash_t *hash,
                                char suffix, size_t *plain_len) {
    char hex[64], obj[PUB_PATH_MAX];
    pub_object_path(px, hash, suffix, hex, sizeof(hex), obj, sizeof(obj));
    size_t slen = 0;
    unsigned char *stored = pub_slurp(obj, &slen);
    if (stored == NULL) {
        pub_fail(px, "object %s missing", hex);
        return NULL;
    }
    cvmfs_hash_t got;
    if (cvmfs_object_hash(CVMFS_HASH_SHA1, stored, slen, &got) != 0
        || !cvmfs_hash_eq(&got, hash)) {
        free(stored);
        pub_fail(px, "object %s fails CAS verification", hex);
        return NULL;
    }
    for (size_t cap = slen * 4 + 65536; cap <= (size_t) 256 * 1024 * 1024; cap *= 2) {
        unsigned char *plain = malloc(cap);
        if (plain == NULL) break;
        if (cvmfs_object_inflate(stored, slen, plain, cap, plain_len) == 0) {
            free(stored);
            return plain;
        }
        free(plain);
    }
    free(stored);
    pub_fail(px, "object %s fails to inflate", hex);
    return NULL;
}

unsigned char *pub_fetch_catalog(pub_ctx_t *px, const cvmfs_hash_t *hash,
                                 size_t *plain_len) {
    return pub_fetch_object(px, hash, 'C', plain_len);
}

pub_cat_t *pub_cat_materialize(pub_ctx_t *px, const char *mount,
                               const cvmfs_hash_t *hash) {
    size_t plen = 0;
    unsigned char *plain = pub_fetch_catalog(px, hash, &plen);
    if (plain == NULL) return NULL;
    pub_cat_t *c = pub_cat_register(px, mount);
    int rc = c != NULL ? pub_spit(c->db, plain, plen, 0) : -1;
    if (rc == 0) {
        snprintf(c->orig_db, sizeof(c->orig_db), "%s.orig", c->db);
        rc = pub_spit(c->orig_db, plain, plen, 0);
    }
    free(plain);
    if (rc != 0 || (c->w = cvmfs_catwriter_open(c->db)) == NULL) {
        pub_fail(px, "cannot open working catalog for %s",
                 mount[0] ? mount : "(root)");
        return NULL;
    }
    return c;
}

pub_cat_t *pub_cat_fresh(pub_ctx_t *px, const char *mount,
                         const cvmfs_catrow_t *rootrow) {
    pub_cat_t *c = pub_cat_register(px, mount);
    if (c == NULL || (c->w = cvmfs_catwriter_create(c->db)) == NULL) {
        pub_fail(px, "cannot create nested catalog for %s", mount);
        return NULL;
    }
    cvmfs_catrow_t root = *rootrow;
    root.path = mount;
    root.flags = CVMFS_FLAG_DIR | CVMFS_FLAG_DIR_NESTED_ROOT;
    c->dirty = 1;
    if (cvmfs_catwriter_insert(c->w, &root) != 0) {
        pub_fail(px, "cannot seed nested catalog root %s", mount);
        return NULL;
    }
    return c;
}

static pub_cat_t *pub_cat_find(pub_ctx_t *px, const char *mount) {
    for (pub_cat_t *c = px->cats; c != NULL; c = c->next)
        if (!c->dropped && strcmp(c->mount, mount) == 0) return c;
    return NULL;
}

typedef struct {
    const char  *mount;
    cvmfs_hash_t hash;
    int          found;
} nested_find_t;

static void pub_nested_cb(const char *path, const char *sha1_hex, uint64_t size,
                          void *ud) {
    nested_find_t *nf = ud;
    (void) size;
    if (!nf->found && strcmp(path, nf->mount) == 0
        && cvmfs_hash_parse(sha1_hex, strlen(sha1_hex), &nf->hash) == 0)
        nf->found = 1;
}

pub_cat_t *pub_owner(pub_ctx_t *px, const char *path) {
    pub_cat_t *cat = px->cats;                       /* root */
    size_t base = 0;
    const char *sep;
    while ((sep = strchr(path + base + 1, '/')) != NULL) {
        char prefix[PUB_PATH_MAX];
        size_t plen = (size_t) (sep - path);
        memcpy(prefix, path, plen);
        prefix[plen] = '\0';
        base = plen;
        pub_cat_t *child = pub_cat_find(px, prefix);
        if (child == NULL) {
            cvmfs_dirent_t de;
            if (cvmfs_catwriter_lookup(cat->w, prefix, &de) != 1
                || !(de.flags & CVMFS_FLAG_DIR_NESTED_MOUNT))
                continue;
            nested_find_t nf = { prefix, {0}, 0 };
            cvmfs_catwriter_list_nested(cat->w, pub_nested_cb, &nf);
            if (!nf.found) {
                pub_fail(px, "mountpoint %s has no nested_catalogs row", prefix);
                return NULL;
            }
            child = pub_cat_materialize(px, prefix, &nf.hash);
            if (child == NULL) return NULL;
            child->parent = cat;
        }
        cat = child;
    }
    return cat;
}

/* ---- changeset application ---------------------------------------------- */

static int pub_apply_delete(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c) {
    cvmfs_dirent_t de;
    int found = cvmfs_catwriter_lookup(cat->w, c->path, &de);
    if (found == 1 && (de.flags & CVMFS_FLAG_DIR_NESTED_MOUNT)
        && cvmfs_catwriter_del_nested(cat->w, c->path) != 0)
        return pub_fail(px, "cannot drop nested row for %s", c->path);
    if (cvmfs_catwriter_delete_subtree(cat->w, c->path) < 0)
        return pub_fail(px, "cannot delete %s", c->path);
    size_t plen = strlen(c->path);
    for (pub_cat_t *k = px->cats; k != NULL; k = k->next)   /* orphaned children */
        if (strncmp(k->mount, c->path, plen) == 0
            && (k->mount[plen] == '\0' || k->mount[plen] == '/'))
            k->dropped = 1;
    cat->dirty = 1;
    return 0;
}

static void pub_row_from_change(cvmfs_catrow_t *r, const cvmfs_change_t *c) {
    memset(r, 0, sizeof(*r));
    r->path = c->path;
    r->mode = c->mode;
    r->mtime = c->mtime;
    r->uid = c->uid;
    r->gid = c->gid;
    r->linkcount = c->linkcount != 0 ? c->linkcount : 1;
    r->hardlink_group = c->hardlink_group;
    r->xattr = c->xattr;
    r->xattr_len = c->xattr_len;
}

static int pub_add_dir(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c,
                       const pub_dirtab_t *dt) {
    cvmfs_dirent_t de;
    int found = cvmfs_catwriter_lookup(cat->w, c->path, &de);
    if (c->opaque && found == 1
        && cvmfs_catwriter_delete_subtree(cat->w, c->path) < 0)
        return pub_fail(px, "cannot clear opaque dir %s", c->path);
    cvmfs_catrow_t r;
    pub_row_from_change(&r, c);
    r.flags = CVMFS_FLAG_DIR;
    if (found == 1 && (de.flags & CVMFS_FLAG_DIR_NESTED_MOUNT) && !c->opaque) {
        r.flags |= CVMFS_FLAG_DIR_NESTED_MOUNT;      /* attr refresh keeps the mount */
    } else if ((found != 1 || c->opaque) && pub_dirtab_new_nests(dt, c->path)) {
        r.flags |= CVMFS_FLAG_DIR_NESTED_MOUNT;      /* new dir the dirtab nests */
        pub_cat_t *child = pub_cat_fresh(px, c->path, &r);
        if (child == NULL) return -1;
        child->parent = cat;
    }
    cat->dirty = 1;
    return cvmfs_catwriter_upsert(cat->w, &r) == 0
        ? 0 : pub_fail(px, "cannot upsert dir %s", c->path);
}

static int pub_store_chunks(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c,
                            int fd, unsigned char *buf) {
    uint64_t off = 0;
    for (;;) {
        ssize_t n = read(fd, buf, (size_t) px->chunk_size);
        if (n < 0) return pub_fail(px, "read error ingesting %s", c->path);
        if (n == 0) break;
        cvmfs_hash_t h;
        if (cvmfs_object_store(&px->store, buf, (size_t) n, 'P', 1, &h, NULL) != 0
            || cvmfs_catwriter_add_chunk(cat->w, c->path, off, (uint64_t) n, &h) != 0)
            return pub_fail(px, "cannot store chunk of %s", c->path);
        off += (uint64_t) n;
    }
    return 0;
}

static int pub_add_file(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c) {
    if (cvmfs_catwriter_delete_subtree(cat->w, c->path) < 0)
        return pub_fail(px, "cannot replace %s", c->path);
    int fd = open(c->src, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (fd >= 0) close(fd);
        return pub_fail(px, "upper file vanished or changed type: %s", c->path);
    }
    cvmfs_catrow_t r;
    pub_row_from_change(&r, c);
    r.size = (uint64_t) st.st_size;
    int chunked = st.st_size > px->chunk_size;
    size_t bufsz = (size_t) (chunked ? px->chunk_size : (st.st_size > 0 ? st.st_size : 1));
    unsigned char *buf = malloc(bufsz);
    int rc;
    cvmfs_hash_t h;
    if (buf == NULL) {
        rc = pub_fail(px, "out of memory ingesting %s", c->path);
    } else if (chunked) {
        r.flags = CVMFS_FLAG_FILE | CVMFS_FLAG_FILE_CHUNK;
        rc = pub_store_chunks(px, cat, c, fd, buf);
    } else {
        r.flags = CVMFS_FLAG_FILE;
        ssize_t n = read(fd, buf, bufsz);
        rc = n == st.st_size
             && cvmfs_object_store(&px->store, buf, (size_t) n, 0, 1, &h, NULL) == 0
             ? 0 : pub_fail(px, "cannot store %s", c->path);
        r.hash = &h;
    }
    free(buf);
    close(fd);
    cat->dirty = 1;
    if (rc == 0 && cvmfs_catwriter_upsert(cat->w, &r) != 0)
        rc = pub_fail(px, "cannot upsert file row %s", c->path);
    return rc;
}

static int pub_add_link(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c) {
    if (cvmfs_catwriter_delete_subtree(cat->w, c->path) < 0)
        return pub_fail(px, "cannot replace %s", c->path);
    cvmfs_catrow_t r;
    pub_row_from_change(&r, c);
    r.flags = CVMFS_FLAG_LINK;
    r.symlink = c->link;
    r.size = strlen(c->link);
    cat->dirty = 1;
    return cvmfs_catwriter_upsert(cat->w, &r) == 0
        ? 0 : pub_fail(px, "cannot upsert symlink %s", c->path);
}

static int pub_apply(pub_ctx_t *px, const cvmfs_changeset_t *cs,
                     const pub_dirtab_t *dt) {
    for (size_t i = 0; i < cs->n; i++) {
        const cvmfs_change_t *c = &cs->v[i];
        pub_cat_t *cat = pub_owner(px, c->path);
        if (cat == NULL) return -1;
        int rc = 0;
        switch (c->op) {
        case CVMFS_CH_DELETE:   rc = pub_apply_delete(px, cat, c); break;
        case CVMFS_CH_ADD_DIR:  rc = pub_add_dir(px, cat, c, dt); break;
        case CVMFS_CH_ADD_FILE: rc = pub_add_file(px, cat, c); break;
        case CVMFS_CH_ADD_LINK: rc = pub_add_link(px, cat, c); break;
        default:                rc = pub_fail(px, "bad change op for %s", c->path);
        }
        if (rc != 0) return -1;
    }
    return 0;
}

/* ---- finalize: bottom-up commit + store + parent nested update ----------- */

static int pub_finalize_one(pub_ctx_t *px, pub_cat_t *c, long new_rev,
                            const char *old_root_hex,
                            cvmfs_hash_t *out_hash, size_t *out_size) {
    char val[32];
    snprintf(val, sizeof(val), "%ld", new_rev);
    int ok = cvmfs_catwriter_set_property(c->w, "revision", val) == 0
          && cvmfs_catwriter_set_property(c->w, "schema", "2.5") == 0
          && cvmfs_catwriter_set_property(c->w, "schema_revision", "2") == 0;
    snprintf(val, sizeof(val), "%ld", (long) time(NULL));
    ok = ok && cvmfs_catwriter_set_property(c->w, "last_modified", val) == 0;
    if (c->mount[0] == '\0')                         /* root extras */
        ok = ok && cvmfs_catwriter_set_property(c->w, "previous_revision",
                                                old_root_hex) == 0;
    else                     /* nested: bind to the mount path (stock rule —
                              * without root_prefix the official client treats
                              * the catalog as rooted at '' and mistranslates) */
        ok = ok && cvmfs_catwriter_set_property(c->w, "root_prefix",
                                                c->mount) == 0;
    if (!ok)
        return pub_fail(px, "cannot set catalog properties for %s",
                        c->mount[0] ? c->mount : "(root)");
    if (cvmfs_catwriter_update_counters(c->w) != 0)
        return pub_fail(px, "cannot update counters for %s", c->mount);
    if (pub_subtree_counters(px, c) != 0)
        return -1;                                   /* err already set */
    if (cvmfs_catwriter_commit(c->w) != 0)
        return pub_fail(px, "cannot commit catalog %s", c->mount);
    c->w = NULL;
    size_t len = 0;
    unsigned char *bytes = pub_slurp(c->db, &len);
    int rc = bytes != NULL
          && cvmfs_object_store(&px->store, bytes, len, 'C', 1, out_hash, NULL) == 0
          ? 0 : pub_fail(px, "cannot store catalog %s", c->mount);
    *out_size = len;
    free(bytes);
    return rc;
}

static int pub_finalize(pub_ctx_t *px, long new_rev, const char *old_root_hex,
                        cvmfs_hash_t *root_hash, size_t *root_size) {
    for (;;) {                       /* deepest dirty mount first; root ends it */
        pub_cat_t *pick = NULL;
        for (pub_cat_t *c = px->cats; c != NULL; c = c->next) {
            if (c->w == NULL) continue;
            if (c->dropped || !c->dirty) {           /* discard untouched/orphaned */
                cvmfs_catwriter_abort(c->w);
                c->w = NULL;
                continue;
            }
            if (pick == NULL || strlen(c->mount) > strlen(pick->mount)) pick = c;
        }
        if (pick == NULL) return pub_fail(px, "nothing to publish%s", "");
        cvmfs_hash_t h;
        size_t sz = 0;
        if (pub_finalize_one(px, pick, new_rev, old_root_hex, &h, &sz) != 0)
            return -1;
        if (pick->mount[0] == '\0') {
            *root_hash = h;
            *root_size = sz;
            return 0;
        }
        char hex[64];
        cvmfs_hash_to_hex(&h, 0, hex, sizeof(hex));
        pub_cat_t *par = pick->parent != NULL ? pick->parent : px->cats;
        if (par->w == NULL
            || cvmfs_catwriter_set_nested(par->w, pick->mount, hex, sz) != 0)
            return pub_fail(px, "cannot update parent nested row for %s", pick->mount);
        par->dirty = 1;
    }
}

/* ---- trust-chain load + manifest swap ------------------------------------ */

int pub_load_and_verify(pub_ctx_t *px) {
    char path[PUB_PATH_MAX], hex[64];
    size_t mlen = 0;
    snprintf(path, sizeof(path), "%s/.cvmfspublished", px->o->repo_dir);
    px->manbuf = pub_slurp(path, &mlen);
    if (px->manbuf == NULL || cvmfs_manifest_parse(px->manbuf, mlen, &px->man) != 0)
        return pub_fail(px, "cannot parse %s", path);
    cvmfs_hash_to_hex(&px->man.certificate, 0, hex, sizeof(hex));
    snprintf(path, sizeof(path), "%s/data/%.2s/%sX", px->o->repo_dir, hex, hex + 2);
    size_t slen = 0;
    unsigned char *stored = pub_slurp(path, &slen);
    unsigned char pem[65536];
    size_t plen = 0;
    int rc = stored != NULL
          && cvmfs_object_inflate(stored, slen, pem, sizeof(pem), &plen) == 0
          && cvmfs_verify_manifest(&px->man, pem, plen) == 0 ? 0 : -1;
    free(stored);
    if (rc != 0)
        return pub_fail(px, "current manifest fails verification — refusing to publish%s", "");
    return 0;
}

int pub_swap_manifest(pub_ctx_t *px, const cvmfs_hash_t *root_hash,
                      size_t root_size, long new_rev) {
    cvmfs_manifest_wr_t wr;
    memset(&wr, 0, sizeof(wr));
    wr.root_catalog = *root_hash;
    wr.catalog_size = (long) root_size;
    wr.certificate = px->man.certificate;
    wr.revision = new_rev;
    wr.fqrn = px->man.repo_name;
    wr.timestamp = (long) time(NULL);
    wr.ttl = px->man.ttl;
    wr.history = px->man.history;

    char reflog[PUB_PATH_MAX];
    snprintf(reflog, sizeof(reflog), "%s/.cvmfsreflog", px->o->repo_dir);
    cvmfs_reflog_t *rl = cvmfs_reflog_open(reflog);
    if (rl == NULL
        || cvmfs_reflog_add(rl, root_hash, CVMFS_REFLOG_CATALOG, wr.timestamp) != 0
        || cvmfs_reflog_close(rl) != 0
        || cvmfs_reflog_checksum(reflog, &wr.reflog_checksum) != 0)
        return pub_fail(px, "cannot append reflog%s", "");

    char keypath[PUB_PATH_MAX], body[2048];
    const char *keys = px->o->keys_dir;
    if (keys != NULL)
        snprintf(keypath, sizeof(keypath), "%s/%s.key", keys, px->man.repo_name);
    else
        snprintf(keypath, sizeof(keypath), "%s/keys/%s.key",
                 px->o->repo_dir, px->man.repo_name);
    EVP_PKEY *key = cvmfs_sign_load_key(keypath);
    int blen = cvmfs_manifest_body(&wr, body, sizeof(body));
    unsigned char art[8192];
    size_t alen = 0;
    int rc = key != NULL && blen > 0
          && cvmfs_sign_artifact((const unsigned char *) body, (size_t) blen,
                                 key, 1, art, sizeof(art), &alen) == 0 ? 0 : -1;
    EVP_PKEY_free(key);
    if (rc != 0)
        return pub_fail(px, "cannot sign manifest with %s", keypath);

    if (getenv("BRIXCVMFS_PUBLISH_CRASH") != NULL)
        _exit(66);                   /* kill-injection point: pre-swap crash */

    char tmp[PUB_PATH_MAX], final[PUB_PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s/.cvmfspublished.tmp.%d",
             px->o->repo_dir, (int) getpid());
    snprintf(final, sizeof(final), "%s/.cvmfspublished", px->o->repo_dir);
    if (pub_spit(tmp, art, alen, 1) != 0 || rename(tmp, final) != 0) {
        unlink(tmp);
        return pub_fail(px, "cannot swap manifest%s", "");
    }
    return 0;
}

/* ---- teardown + entry ---------------------------------------------------- */

static void pub_teardown(pub_ctx_t *px) {
    pub_cat_t *c = px->cats;
    while (c != NULL) {
        pub_cat_t *n = c->next;
        if (c->w != NULL) cvmfs_catwriter_abort(c->w);
        if (c->db[0]) unlink(c->db);
        if (c->orig_db[0]) unlink(c->orig_db);
        free(c);
        c = n;
    }
    px->cats = NULL;
    if (px->workdir[0]) rmdir(px->workdir);
    cvmfs_objstore_close(&px->store);
    free(px->manbuf);
}

int cvmfs_publish_run(const cvmfs_publish_opts_t *o, const cvmfs_changeset_t *cs,
                      long *new_revision, char *err, size_t errlen) {
    pub_ctx_t px;
    memset(&px, 0, sizeof(px));
    px.o = o;
    px.err = err;
    px.errlen = errlen;
    px.chunk_size = o->chunk_size != 0 ? o->chunk_size : CVMFS_PUBLISH_CHUNK_DEFAULT;
    if (px.chunk_size < CVMFS_PUBLISH_CHUNK_FLOOR)
        return pub_fail(&px, "chunk size below the 4096-byte floor%s", "");
    if (px.chunk_size > CVMFS_PUBLISH_CHUNK_CEIL)
        return pub_fail(&px, "chunk size above the %ld-byte ceiling "
                             "(a larger object cannot be read back)",
                        CVMFS_PUBLISH_CHUNK_CEIL);
    snprintf(px.workdir, sizeof(px.workdir), "%s/.brix.publish.tmp", o->repo_dir);
    if (mkdir(px.workdir, 0755) != 0 && errno != EEXIST)
        return pub_fail(&px, "cannot create %s", px.workdir);
    if (cvmfs_objstore_open(&px.store, o->repo_dir) != 0)
        return pub_fail(&px, "cannot open object store under %s", o->repo_dir);

    pub_dirtab_t dt;
    memset(&dt, 0, sizeof(dt));
    long new_rev = 0;
    char old_root_hex[64];
    cvmfs_hash_t root_hash;
    size_t root_size = 0;
    int rc = pub_load_and_verify(&px);
    if (rc == 0) {
        new_rev = px.man.revision + 1;
        cvmfs_hash_to_hex(&px.man.root_catalog, 0, old_root_hex, sizeof(old_root_hex));
        rc = pub_cat_materialize(&px, "", &px.man.root_catalog) != NULL ? 0 : -1;
    }
    if (rc == 0) rc = pub_dirtab_load(&px, o->dirtab, &dt);
    if (rc == 0) rc = pub_dirtab_markers(&px, &dt, cs);
    if (rc == 0) rc = pub_dirtab_apply(&px, &dt);
    if (rc == 0) rc = pub_apply(&px, cs, &dt);
    if (rc == 0) rc = pub_finalize(&px, new_rev, old_root_hex, &root_hash, &root_size);
    if (rc == 0) rc = pub_swap_manifest(&px, &root_hash, root_size, new_rev);
    if (rc == 0 && new_revision != NULL) *new_revision = new_rev;
    pub_dirtab_free(&dt);
    pub_teardown(&px);
    return rc;
}
