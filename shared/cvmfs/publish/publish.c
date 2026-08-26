/* publish.c — the publish engine: changeset → new signed revision.
 * See publish.h; catalog tree plumbing shared with publish_dirtab.c via
 * publish_internal.h. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* fsync/getpid & friends under -std=c11 */
#endif
#include "cvmfs/publish/publish_internal.h"
#include "cvmfs/object/object.h"
#include "cvmfs/platform/platform.h"
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

#include "publish_apply.c"
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

/* The store runs in no_fsync batch mode (one barrier beats one fsync per
 * object); nothing the new manifest names may still be volatile when the
 * swap makes it live. */
static int pub_sync_store(pub_ctx_t *px) {
    int fd = open(px->o->repo_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int rc = fd >= 0 && brix_plat_sync_tree(fd) == 0 ? 0 : -1;
    if (fd >= 0) close(fd);
    return rc == 0 ? 0
         : pub_fail(px, "cannot flush object store under %s", px->o->repo_dir);
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

/*
 * WHAT: Validate publish sizing and open its private workspace and object store.
 * WHY:  The mutation pipeline should begin only from a fully initialized context.
 * HOW:  Apply chunk bounds, create the work directory, and enable batched fsync.
 */
static int pub_prepare(pub_ctx_t *px, const cvmfs_publish_opts_t *opts,
                       char *err, size_t errlen) {
    px->o = opts;
    px->err = err;
    px->errlen = errlen;
    px->chunk_size = opts->chunk_size != 0 ? opts->chunk_size :
                                             CVMFS_PUBLISH_CHUNK_DEFAULT;
    if (px->chunk_size < CVMFS_PUBLISH_CHUNK_FLOOR)
        return pub_fail(px, "chunk size below the 4096-byte floor%s", "");
    if (px->chunk_size > CVMFS_PUBLISH_CHUNK_CEIL) {
        char ceiling[32];

        snprintf(ceiling, sizeof(ceiling), "%ld", CVMFS_PUBLISH_CHUNK_CEIL);
        return pub_fail(px, "chunk size above the %s-byte ceiling "
                            "(a larger object cannot be read back)", ceiling);
    }
    snprintf(px->workdir, sizeof(px->workdir), "%s/.brix.publish.tmp",
             opts->repo_dir);
    if (mkdir(px->workdir, 0755) != 0 && errno != EEXIST)
        return pub_fail(px, "cannot create %s", px->workdir);
    if (cvmfs_objstore_open(&px->store, opts->repo_dir) != 0)
        return pub_fail(px, "cannot open object store under %s", opts->repo_dir);
    px->store.cas.no_fsync = 1;
    return 0;
}

/*
 * WHAT: Execute the ordered catalog mutation and publication pipeline.
 * WHY:  Each phase depends on the authenticated output of every preceding phase.
 * HOW:  Stop on first failure, sync named objects, then atomically swap manifest.
 */
static int pub_run_pipeline(pub_ctx_t *px, const cvmfs_changeset_t *changeset,
                            pub_dirtab_t *dirtab, long *revision) {
    char         old_root_hex[64];
    cvmfs_hash_t root_hash;
    size_t       root_size = 0;
    int          rc = pub_load_and_verify(px);

    if (rc != 0)
        return rc;
    *revision = px->man.revision + 1;
    cvmfs_hash_to_hex(&px->man.root_catalog, 0, old_root_hex,
                      sizeof(old_root_hex));
    if (pub_cat_materialize(px, "", &px->man.root_catalog) == NULL)
        return -1;
    if (pub_dirtab_load(px, px->o->dirtab, dirtab) != 0 ||
        pub_dirtab_markers(px, dirtab, changeset) != 0 ||
        pub_dirtab_apply(px, dirtab) != 0 ||
        pub_apply(px, changeset, dirtab) != 0 ||
        pub_finalize(px, *revision, old_root_hex, &root_hash, &root_size) != 0 ||
        pub_sync_store(px) != 0)
        return -1;
    return pub_swap_manifest(px, &root_hash, root_size, *revision);
}

int cvmfs_publish_run(const cvmfs_publish_opts_t *o, const cvmfs_changeset_t *cs,
                      long *new_revision, char *err, size_t errlen) {
    pub_ctx_t px;
    pub_dirtab_t dt;
    long new_rev = 0;
    int rc;

    memset(&px, 0, sizeof(px));
    memset(&dt, 0, sizeof(dt));
    rc = pub_prepare(&px, o, err, errlen);
    if (rc != 0)
        return rc;
    rc = pub_run_pipeline(&px, cs, &dt, &new_rev);
    if (rc == 0 && new_revision != NULL)
        *new_revision = new_rev;
    pub_dirtab_free(&dt);
    pub_teardown(&px);
    return rc;
}
