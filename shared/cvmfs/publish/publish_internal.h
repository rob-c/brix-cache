/* publish_internal.h — engine context shared by publish.c / publish_dirtab.c. */
#ifndef BRIX_CVMFS_PUBLISH_INTERNAL_H
#define BRIX_CVMFS_PUBLISH_INTERNAL_H

#include "cvmfs/publish/publish.h"
#include "cvmfs/catalog/catalog.h"
#include "cvmfs/catalog/catalog_write.h"
#include "cvmfs/object/object_write.h"
#include "cvmfs/signature/manifest.h"

#define PUB_PATH_MAX 1024

/* One open catalog working copy. `mount` is "" for the root catalog, else the
 * repo-relative mountpoint path. `orig_db` is a pristine copy of the fetched
 * DB kept for reader-side enumeration (splits); fresh catalogs have none. */
#define PUB_NCOUNTERS 9              /* the self/subtree counter family */
extern const char *const pub_counter_names[PUB_NCOUNTERS];

typedef struct pub_cat_s {
    char               mount[PUB_PATH_MAX];
    char               db[PUB_PATH_MAX + 32];
    char               orig_db[PUB_PATH_MAX + 48];   /* "" when fresh */
    cvmfs_catwriter_t *w;
    struct pub_cat_s  *parent;
    struct pub_cat_s  *next;
    int                dirty;
    int                dropped;      /* subtree deleted; do not finalize */
    int64_t            tot[PUB_NCOUNTERS];   /* self+subtree, set at finalize */
    int                has_tot;
} pub_cat_t;

typedef struct {
    const cvmfs_publish_opts_t *o;
    cvmfs_objstore_t            store;
    cvmfs_manifest_t            man;             /* current (old) manifest */
    unsigned char              *manbuf;
    char                        workdir[PUB_PATH_MAX];
    pub_cat_t                  *cats;            /* head = root catalog */
    long                        chunk_size;
    int                         seq;             /* working-file counter */
    char                       *err;
    size_t                      errlen;
} pub_ctx_t;

/* Error helper: snprintf into ctx->err, return -1. */
int pub_fail(pub_ctx_t *px, const char *fmt, const char *arg);

/* Whole-file read/write helpers (publish.c). */
unsigned char *pub_slurp(const char *path, size_t *len);
int pub_spit(const char *path, const unsigned char *buf, size_t len, int do_sync);

/* Fetch + CAS-identity-verify + inflate the catalog object `hash`; returns a
 * malloc'd plain DB image (caller frees) or NULL with ctx->err set. */
unsigned char *pub_fetch_catalog(pub_ctx_t *px, const cvmfs_hash_t *hash,
                                 size_t *plain_len);

/* Same, for any CAS suffix ('C' catalog, 'H' history, 'X' cert, 0 content). */
unsigned char *pub_fetch_object(pub_ctx_t *px, const cvmfs_hash_t *hash,
                                char suffix, size_t *plain_len);

/* Existence + CAS identity of a stored object WITHOUT inflating it — an
 * integrity sweep must not pay decompression on every object in the
 * repository. `what` names the referring path in the failure message. */
int pub_verify_object(pub_ctx_t *px, const cvmfs_hash_t *hash, char suffix,
                      const char *what);

/* Slurp + parse <repo>/.cvmfspublished into px->man/px->manbuf and verify its
 * signature against the CAS-stored certificate. 0/-1 (publish.c). */
int pub_load_and_verify(pub_ctx_t *px);

/* Append `root_hash` to the reflog, recompute 'Y', sign the new manifest body
 * (root/new_rev + px->man's cert/ttl/history/fqrn) with <keys>/<fqrn>.key and
 * atomically swap .cvmfspublished (publish.c). 0/-1. */
int pub_swap_manifest(pub_ctx_t *px, const cvmfs_hash_t *root_hash,
                      size_t root_size, long new_rev);

/* Aggregate the subtree_* counters of `c` from its nested children (open
 * children use their finalize totals; untouched ones are fetched from CAS),
 * then record c->tot = self + subtree. Call after update_counters, before
 * commit (publish_counters.c). */
int pub_subtree_counters(pub_ctx_t *px, pub_cat_t *c);

/* Fetch catalog `hash` from CAS, inflate to a fresh working file, open a
 * catwriter on it and register it (with a pristine orig copy). NULL on error. */
pub_cat_t *pub_cat_materialize(pub_ctx_t *px, const char *mount,
                               const cvmfs_hash_t *hash);

/* Create a FRESH nested catalog rooted at `mount` (root row from `rootrow`,
 * which carries plain-dir attrs; the NESTED_ROOT flag is added here). */
pub_cat_t *pub_cat_fresh(pub_ctx_t *px, const char *mount,
                         const cvmfs_catrow_t *rootrow);

/* The deepest open-or-discoverable catalog owning `path` (descends through
 * NESTED_MOUNT rows, materializing children on demand). NULL on error. */
pub_cat_t *pub_owner(pub_ctx_t *px, const char *path);

/* ---- dirtab pre-pass (publish_dirtab.c) --------------------------------- */

typedef struct {
    char **pat;         /* patterns; pat[i][0] == '!' → negation */
    size_t n;
    char **madd;        /* dirs gaining a .cvmfscatalog marker this changeset */
    size_t n_madd;
    char **mdel;        /* dirs whose marker is whited-out this changeset */
    size_t n_mdel;
} pub_dirtab_t;

/* Parse the dirtab file. 0 on success (dt->n == 0 when path is NULL/absent);
 * -1 with a line-numbered message on malformed/unsafe lines. */
int  pub_dirtab_load(pub_ctx_t *px, const char *path, pub_dirtab_t *dt);
void pub_dirtab_free(pub_dirtab_t *dt);

/* 1 when `path` matches the dirtab (last match wins; '!' negates). */
int pub_dirtab_match(const pub_dirtab_t *dt, const char *path);

/* Collect the .cvmfscatalog marker deltas of `cs` into dt->madd / dt->mdel
 * (official-grammar equivalent of a dirtab entry: a marker file in a dir
 * nests it). 0/-1. */
int pub_dirtab_markers(pub_ctx_t *px, pub_dirtab_t *dt,
                       const cvmfs_changeset_t *cs);

/* 1 when a dir NEW in this changeset must be born nested (dirtab match or a
 * marker arriving with it). */
int pub_dirtab_new_nests(const pub_dirtab_t *dt, const char *path);

/* Pre-pass over the CURRENT tree: split plain dirs that now match the dirtab
 * (or gain a marker), dissolve mountpoints that no longer match (or lose
 * their marker). Marker-nested mounts persist without dirtab rules. 0/-1. */
int pub_dirtab_apply(pub_ctx_t *px, const pub_dirtab_t *dt);

#endif /* BRIX_CVMFS_PUBLISH_INTERNAL_H */
