/*
 * gcas.h — phase-87 G13: cross-repo dedup of verified CVMFS CAS objects.
 *
 * WHAT: hardlink-identity dedup for the LOCAL posix cache store — every
 *       cvmfs-cas-verified /cvmfs/<repo>/data/ object also carries a canonical
 *       repo-agnostic name under <store>/.gcas/, so byte-identical objects
 *       referenced by several repos share ONE inode.
 * WHY:  stratum mirrors publish the same objects under many repo prefixes and
 *       the cache key is the client-visible per-repo path, so identical
 *       content was stored once per repo. Content addressing plus the
 *       verify-on-fill proof make hash identity safe to collapse — but only
 *       at the byte layer: keys, cinfo records, authz and origin fetches stay
 *       strictly per-repo, so a repo can never serve bytes its own origin has
 *       not proven it holds (each repo still fills — and 404s — through its
 *       own origin; dedup begins only after that verified fill commits).
 * HOW:  publish (post-commit, cvmfs-cas-verified fills only) links the
 *       committed object and the canonical name onto one inode; evict GC
 *       unlinks the canonical once it is the last remaining name. The
 *       filesystem's link count IS the combined refcount — a shared object
 *       survives until its last per-repo reference is evicted and there is no
 *       bookkeeping to corrupt or double-free. Every step is best-effort: any
 *       failure leaves plain, correct per-repo copies.
 */
#ifndef BRIX_CACHE_GCAS_H
#define BRIX_CACHE_GCAS_H

#include "cstore.h"

/* Map a cache key onto its canonical repo-agnostic store name
 * ("/.gcas/<2hex>/<hex...><suffix>"). Returns 0 and fills dst only for a
 * CVMFS immutable-CAS key (classify.h); -1 for every other key shape. */
int brix_gcas_canonical_rel(const char *key, char *dst, size_t cap);

/* Post-commit publish: bind the committed object at `key` and its canonical
 * name to one inode (register the first appearance, adopt the canonical for
 * every later byte-identical fill). Call ONLY for cvmfs-cas-verified fills —
 * the key's hash must be a proven content address. Best-effort: on any
 * failure the per-repo copy stays as committed. */
void brix_gcas_publish(brix_cstore_t *cs, const char *key);

/* Post-evict GC: unlink the canonical name once the evicted key was its last
 * data link (st_nlink == 1). Safe on any key — non-CAS keys no-op. */
void brix_gcas_evict_gc(brix_cstore_t *cs, const char *key);

#endif /* BRIX_CACHE_GCAS_H */
