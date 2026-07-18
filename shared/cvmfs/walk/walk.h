/* walk.h — CVMFS content-aware core facade (pure C, no ngx/FUSE).
 *
 * WHAT: the two "content-aware" questions both surfaces ask of a snapshot —
 *       cvmfs_walk_catalog() enumerates every CAS reference a root catalog
 *       reaches (catalogs, whole files, chunks), and cvmfs_verify_blob()
 *       verifies + decodes one stored CAS object outside the fetch orchestrator.
 * WHY:  prefetch (F4), prewarm (F5) and the proxy-side features need "walk a
 *       snapshot" / "verify a blob" where today only the FUSE read stack
 *       composes those primitives. Build the seam once (phase-85 F0).
 * HOW:  pure composition — catalogs are pulled through the hash-verifying fetch
 *       orchestrator (so a tampered catalog aborts the walk), spilled to a temp
 *       file, read with the catalog reader, recursed at nested-catalog
 *       mountpoints. No new I/O primitives.
 */
#ifndef BRIX_CVMFS_WALK_H
#define BRIX_CVMFS_WALK_H

#include <stddef.h>
#include <stdint.h>
#include "cvmfs/grammar/hash.h"
#include "cvmfs/fetch/fetch.h"

typedef enum {
    CVMFS_WALK_CATALOG = 0,   /* a catalog object ('C') — root and nested */
    CVMFS_WALK_FILE,          /* a whole-file content object (no suffix) */
    CVMFS_WALK_CHUNK          /* a partial-file chunk ('P') */
} cvmfs_walk_kind_e;

typedef struct {
    cvmfs_walk_kind_e kind;
    cvmfs_hash_t      hash;
    char              suffix;   /* 'C' / 0 / 'P' — ready for cvmfs_fetch_object */
    uint64_t          size;     /* plaintext size where the catalog records one, else 0 */
    const char       *path;     /* repo-root-relative path of the owning entry ("" = root) */
} cvmfs_walk_item_t;

/* Return 0 to continue, nonzero to stop the walk early. */
typedef int (*cvmfs_walk_cb)(const cvmfs_walk_item_t *item, void *ud);

/* Enumerate every CAS reference reachable from root catalog `root`: the root
 * catalog itself, each regular file's content object (or its chunks), and each
 * nested catalog (emitted, then descended into) down to `max_depth` nesting
 * levels (0 = root catalog only). Catalogs are fetched VERIFIED through `fx`
 * and spilled under `tmp_dir`. Returns 0 on a complete walk, 1 if the callback
 * stopped it, -1 on a fetch/open error (walk aborted). */
int cvmfs_walk_catalog(cvmfs_fetch_ctx_t *fx, const cvmfs_hash_t *root,
                       const char *tmp_dir, int max_depth,
                       cvmfs_walk_cb cb, void *ud, long now);

/* Subtree-scoped walk: like cvmfs_walk_catalog, but enumerate only the CAS
 * references under directory `path` ("" = repo root, then equivalent to a full
 * walk without the root-catalog item). Navigates across nested-catalog
 * mountpoints covering `path` first (each hop hash-verified), then walks the
 * subtree down to `max_depth` further nesting levels. A `path` absent from the
 * snapshot yields an empty walk (rc 0). Same return codes as
 * cvmfs_walk_catalog. */
int cvmfs_walk_subtree(cvmfs_fetch_ctx_t *fx, const cvmfs_hash_t *root,
                       const char *tmp_dir, const char *path, int max_depth,
                       cvmfs_walk_cb cb, void *ud, long now);

/* Verify one STORED CAS object (bytes as served: zlib-compressed or plain) and
 * decode it: the stored bytes must hash to `expected` (CVMFS object identity is
 * the stored-form hash — same rule as the fetch orchestrator), then the
 * plaintext (inflated, or the raw bytes when not a zlib stream) is written to
 * `out`. Returns 0 verified, -1 hash mismatch, -3 `out` too small. */
int cvmfs_verify_blob(const cvmfs_hash_t *expected,
                      const unsigned char *stored, size_t stored_len,
                      unsigned char *out, size_t outcap, size_t *outlen);

#endif /* BRIX_CVMFS_WALK_H */
