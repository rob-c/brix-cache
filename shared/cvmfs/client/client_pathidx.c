/* client_pathidx.c — G6 mmap path-index lifecycle (phase-87).
 *
 * WHAT: build/load/clear the client's mmap'd namespace index; the resolve/
 *       readdir/read fast paths themselves live in client.c.
 * WHY:  the index is only trustworthy when built from a VERIFIED catalog walk
 *       and only meaningful while bound to the root catalog actually being
 *       served — this file owns both rules (the G1 filter's discipline), so
 *       every consumer (FUSE opt, sidecar reload, tests) goes through the
 *       same fail-closed gate.
 * HOW:  cvmfs_walk_paths() (every hop hash-verified) feeds full dirents into
 *       the pathidx builder, the sidecar is written tmp+rename under the
 *       cache dirfd, then mmap'd back and adopted iff its recorded root still
 *       equals the served root. Any failure leaves the index INACTIVE —
 *       lookups stay live on the catalogs.
 */
#include "cvmfs/client/client.h"
#include "cvmfs/walk/walk.h"

#define PIDX_WALK_DEPTH 64   /* nested-catalog descent bound (matches G1) */

static const cvmfs_hash_t *served_root(const cvmfs_client_t *cl) {
    return cl->pin_set ? &cl->pin_root : &cl->manifest.root_catalog;
}

static int pidx_visit(const cvmfs_walk_item_t *it, void *ud) {
    cvmfs_pathidx_build_t *b = ud;
    if (it->kind != CVMFS_WALK_DENT || it->dent == NULL) return 0;
    return cvmfs_pathidx_build_add(b, it->path, it->dent) != 0;  /* oom stops */
}

int cvmfs_client_pathidx_load(cvmfs_client_t *cl, int dfd, const char *name) {
    cvmfs_pathidx_t ix;
    if (cvmfs_pathidx_open(&ix, dfd, name) != 0) return -1;
    if (!cvmfs_hash_eq(cvmfs_pathidx_root(&ix), served_root(cl))) {
        cvmfs_pathidx_close(&ix);   /* another revision's index: never answers */
        return -1;
    }
    cvmfs_client_pathidx_clear(cl);
    cl->pidx = ix;
    cl->pidx_root = *cvmfs_pathidx_root(&cl->pidx);
    cl->pidx_set = 1;
    return 0;
}

int cvmfs_client_pathidx_build(cvmfs_client_t *cl, int dfd, const char *name,
                               long now) {
    cvmfs_hash_t root = *served_root(cl);
    const char *tmp = cl->catalog_tmp[0] ? cl->catalog_tmp : "/tmp";

    cvmfs_pathidx_build_t b;
    cvmfs_pathidx_build_init(&b);

    /* The repo root "" is not a named walk entry — seed it from the catalog. */
    cvmfs_dirent_t rootent;
    if (cvmfs_catalog_lookup(cl->root_catalog, "", &rootent) != 1
        || cvmfs_pathidx_build_add(&b, "", &rootent) != 0) {
        cvmfs_pathidx_build_free(&b);
        return -1;
    }
    /* The build is opportunistic: its walk may fail on repos whose nested
     * catalogs are missing/tampered, and those failures blacklist endpoints
     * in the shared failover engine — on a single-host mount that would
     * push the WHOLE mount offline and take the catalog fallback down with
     * it. A failed build must leave transport health exactly as it found
     * it (the engine is a flat struct — snapshot/restore is a copy). */
    cvmfs_failover_t fo_snap;
    if (cl->fetch.fo != NULL) fo_snap = *cl->fetch.fo;
    int rc = cvmfs_walk_paths(&cl->fetch, &root, tmp, PIDX_WALK_DEPTH,
                              pidx_visit, &b, now);
    if (rc != 0 || b.oom) {   /* incomplete namespace ⇒ fabricated ENOENTs */
        if (cl->fetch.fo != NULL) *cl->fetch.fo = fo_snap;
        cvmfs_pathidx_build_free(&b);
        return -1;
    }
    rc = cvmfs_pathidx_write(&b, &root, dfd, name);
    cvmfs_pathidx_build_free(&b);
    if (rc != 0) return -1;
    return cvmfs_client_pathidx_load(cl, dfd, name);
}

void cvmfs_client_pathidx_clear(cvmfs_client_t *cl) {
    if (cl->pidx_set) cvmfs_pathidx_close(&cl->pidx);
    cl->pidx_set = 0;
}

int cvmfs_client_pathidx_active(const cvmfs_client_t *cl) {
    return cl->pidx_set;
}
