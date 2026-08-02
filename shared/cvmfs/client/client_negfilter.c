/* client_negfilter.c — G1 negative-lookup filter lifecycle (phase-87).
 *
 * WHAT: build/adopt/inspect/clear the client's xor filter over the served
 *       revision's path-set; the resolve-time short-circuit itself lives in
 *       client.c (cvmfs_client_resolve).
 * WHY:  the filter is only trustworthy when built from a VERIFIED catalog walk
 *       and only meaningful while bound to the root catalog actually being
 *       served — this file owns both rules so every consumer (FUSE opt,
 *       sidecar reload, tests) goes through the same fail-closed gate.
 * HOW:  cvmfs_walk_paths() (every hop hash-verified through the fetch
 *       orchestrator) feeds path keys into a growable array, cvmfs_xorf_build
 *       peels the filter, and adopt binds it to the served root. Any failure
 *       leaves the filter INACTIVE — lookups stay live, never a fabricated
 *       ENOENT.
 */
#include "cvmfs/client/client.h"
#include "cvmfs/walk/walk.h"

#include <stdlib.h>
#include <string.h>

#define NEGF_WALK_DEPTH 64   /* nested-catalog descent bound (matches client) */

static const cvmfs_hash_t *served_root(const cvmfs_client_t *cl) {
    return cl->pin_set ? &cl->pin_root : &cl->manifest.root_catalog;
}

typedef struct {
    uint64_t *keys;
    size_t    n, cap;
    int       oom;
} negf_keys_t;

static int negf_visit(const cvmfs_walk_item_t *it, void *ud) {
    negf_keys_t *k = ud;
    if (it->kind != CVMFS_WALK_DENT) return 0;
    if (k->n == k->cap) {
        size_t ncap = k->cap ? k->cap * 2 : 4096;
        if (ncap > CVMFS_XORF_MAX_KEYS) { k->oom = 1; return 1; }
        uint64_t *nk = realloc(k->keys, ncap * sizeof(*nk));
        if (nk == NULL) { k->oom = 1; return 1; }
        k->keys = nk;
        k->cap = ncap;
    }
    k->keys[k->n++] = cvmfs_xorf_key(it->path);
    return 0;
}

int cvmfs_client_negfilter_adopt(cvmfs_client_t *cl, cvmfs_xorf_t *f,
                                 const cvmfs_hash_t *root) {
    if (f->fp == NULL) return -1;
    if (!cvmfs_hash_eq(root, served_root(cl))) return -1;   /* wrong revision */
    cvmfs_xorf_reset(&cl->negf);
    cl->negf = *f;
    memset(f, 0, sizeof(*f));   /* heap ownership moved into the client */
    cl->negf_root = *root;
    cl->negf_set = 1;
    return 0;
}

int cvmfs_client_negfilter_build(cvmfs_client_t *cl, long now) {
    cvmfs_hash_t root = *served_root(cl);
    const char *tmp = cl->catalog_tmp[0] ? cl->catalog_tmp : "/tmp";

    negf_keys_t k;
    memset(&k, 0, sizeof(k));
    int rc = cvmfs_walk_paths(&cl->fetch, &root, tmp, NEGF_WALK_DEPTH,
                              negf_visit, &k, now);
    if (rc != 0 || k.oom) {   /* incomplete path-set ⇒ unusable (false negs) */
        free(k.keys);
        return -1;
    }

    cvmfs_xorf_t f;
    rc = cvmfs_xorf_build(&f, k.keys, k.n);
    free(k.keys);
    if (rc != 0) return -1;

    if (cvmfs_client_negfilter_adopt(cl, &f, &root) != 0) {
        cvmfs_xorf_reset(&f);   /* served root changed under us — drop it */
        return -1;
    }
    return 0;
}

const cvmfs_xorf_t *cvmfs_client_negfilter(const cvmfs_client_t *cl,
                                           cvmfs_hash_t *root_out) {
    if (!cl->negf_set) return NULL;
    if (root_out) *root_out = cl->negf_root;
    return &cl->negf;
}

void cvmfs_client_negfilter_clear(cvmfs_client_t *cl) {
    cvmfs_xorf_reset(&cl->negf);
    cl->negf_set = 0;
}
