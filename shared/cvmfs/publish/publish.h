/* publish.h — apply a changeset to a repository: the publish engine
 * (phase-96 S5 catalog delta · S6 dirtab nesting · S7 chunking).
 *
 * WHAT: verify the current trust chain, materialize working copies of the
 *       affected catalogs, apply the changeset bottom-up (a rewritten nested
 *       catalog updates its parent's nested_catalogs row up to the root),
 *       chunk large files, honor .cvmfsdirtab, bump the revision, append the
 *       reflog, re-sign, and swap `.cvmfspublished` LAST (atomic rename) so a
 *       crashed publish never leaves a half-visible revision.
 * WHY:  tool-surface publishing (G14 ruling) — this links into brixcvmfs
 *       only, never into nginx workers.
 * HOW:  catalogs are fetched from CAS, inflated to working files, mutated via
 *       catalog_write.c, then compressed + CAS-stored; unchanged nested
 *       catalogs are untouched, so publish cost scales with the touched
 *       subtree. CAS puts are idempotent (immutable-put), so a crashed
 *       publish is safely re-runnable.
 */
#ifndef BRIX_CVMFS_PUBLISH_H
#define BRIX_CVMFS_PUBLISH_H

#include <stddef.h>
#include "cvmfs/publish/changeset.h"

#define CVMFS_PUBLISH_CHUNK_DEFAULT (32L * 1024 * 1024)
#define CVMFS_PUBLISH_CHUNK_FLOOR   4096L

typedef struct {
    const char *repo_dir;
    const char *keys_dir;     /* NULL → "<repo_dir>/keys" */
    const char *dirtab;       /* explicit .cvmfsdirtab path; NULL = none */
    long        chunk_size;   /* 0 → CVMFS_PUBLISH_CHUNK_DEFAULT; < FLOOR refused */
} cvmfs_publish_opts_t;

/* Run one publish. On success returns 0 and sets *new_revision; on failure
 * returns -1 with a message in err and the published revision untouched.
 * Test hook: when $BRIXCVMFS_PUBLISH_CRASH is set, _exit(66) right before the
 * manifest swap — the kill-injection point for the crash-safety tests. */
int cvmfs_publish_run(const cvmfs_publish_opts_t *o, const cvmfs_changeset_t *cs,
                      long *new_revision, char *err, size_t errlen);

/* Reader-only integrity check: recompute every catalog's self/subtree
 * counters from its actual rows and flag drift, malformed xattr BLOBs and
 * unreachable nested catalogs. With check_data also CAS-verifies the
 * certificate and every referenced payload object (whole-file and chunk) —
 * the on-disk rot sweep, linear in repository size. Never writes to the
 * repository. 0 healthy, -1 with a message in err (fsck.c). */
int cvmfs_fsck_run(const char *repo_dir, int check_data, char *err, size_t errlen);

#endif /* BRIX_CVMFS_PUBLISH_H */
