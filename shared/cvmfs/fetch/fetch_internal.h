/* fetch_internal.h — cross-TU seam for the fetch orchestrator internals.
 *
 * WHAT: the decode/verify and verified-store steps of cvmfs_fetch_object,
 *       shared with the bundle ingest (fetch_bundle.c) so a bundle member
 *       goes through the IDENTICAL stored-form hash verify + sidecar store
 *       the single-object path uses.
 * WHY:  the phase-87 G2 bundle is a transport optimization only — trust must
 *       stay per-object and single-sourced; two implementations of "verify a
 *       CAS object" would inevitably drift.
 * HOW:  formerly-static fetch.c helpers, renamed and declared here (mirror of
 *       the cvmfs_module_internal.h idiom on the server side). Not part of
 *       the public fetch surface (that lives in fetch.h).
 */
#ifndef BRIX_CVMFS_FETCH_INTERNAL_H
#define BRIX_CVMFS_FETCH_INTERNAL_H

#include "cvmfs/fetch/fetch.h"

/* Verify `raw` (stored-form bytes) against `hash`, then produce plaintext in
 * `out` per ctx->store_form. Returns 0 verified, -1 hash mismatch (poisoned/
 * corrupt — the bytes must not be used), -3 out too small. */
int cvmfs_fetch_decode_verify(cvmfs_fetch_ctx_t *ctx, const cvmfs_hash_t *hash,
                              const unsigned char *raw, size_t rawlen,
                              unsigned char *out, size_t outcap, size_t *outlen);

/* Store verified plaintext + its integrity sidecar under `key`. Best-effort:
 * a failed sidecar put just means the entry re-verifies as a miss later. */
void cvmfs_fetch_cache_put(brix_cas_store_t *cache, const char *key,
                           cvmfs_hash_algo_e algo,
                           const unsigned char *plain, size_t len);

#endif /* BRIX_CVMFS_FETCH_INTERNAL_H */
