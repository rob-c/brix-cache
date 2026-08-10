/*
 * gcas.h — phase-87 G13: cross-repo dedup of verified CVMFS CAS objects.
 *
 * WHAT: content-identity dedup for the cache store — every cvmfs-cas-verified
 *       /cvmfs/<repo>/data/ object is published to the store driver's
 *       dedup_publish slot with its canonical repo-agnostic alias
 *       ("/.gcas/<2hex>/<hex><sfx>"), so byte-identical objects referenced by
 *       several repos collapse onto ONE stored copy.
 * WHY:  stratum mirrors publish the same objects under many repo prefixes and
 *       the cache key is the client-visible per-repo path, so identical
 *       content was stored once per repo. Content addressing plus the
 *       verify-on-fill proof make hash identity safe to collapse — but only
 *       at the byte layer: keys, cinfo records, authz and origin fetches stay
 *       strictly per-repo, so a repo can never serve bytes its own origin has
 *       not proven it holds (each repo still fills — and 404s — through its
 *       own origin; dedup begins only after that verified fill commits).
 * HOW:  phase-88 W1 made the mechanics a driver verb: posix stores hardlink
 *       the key and the canonical onto one inode (st_nlink is the refcount;
 *       evict GC reaps a last-link canonical), pblock stores fold
 *       byte-identical blobs via F10 refcounting (no alias GC needed). This
 *       layer keeps the CVMFS classify gate + canonical-name grammar. Every
 *       step is best-effort: any failure leaves plain, correct per-repo
 *       copies.
 */
#ifndef BRIX_CACHE_GCAS_H
#define BRIX_CACHE_GCAS_H

#include "cstore.h"

/* Map a cache key onto its canonical repo-agnostic store name
 * ("/.gcas/<2hex>/<hex...><suffix>"). Returns 0 and fills dst only for a
 * CVMFS immutable-CAS key (classify.h); -1 for every other key shape. */
int brix_gcas_canonical_rel(const char *key, char *dst, size_t cap);

/* Post-commit publish: hand the committed object at `key` and its canonical
 * alias to the store driver's dedup_publish slot (posix: register/adopt the
 * canonical inode; pblock: fold byte-identical blobs). Call ONLY for
 * cvmfs-cas-verified fills — the key's hash must be a proven content address.
 * Best-effort: on any failure the per-repo copy stays as committed. */
void brix_gcas_publish(brix_cstore_t *cs, const char *key);

/* Post-evict GC: hand the evicted key's canonical alias to the store driver's
 * dedup_gc slot (posix: unlink a last-link canonical; refcounting stores have
 * no slot and no-op). Safe on any key — non-CAS keys no-op. */
void brix_gcas_evict_gc(brix_cstore_t *cs, const char *key);

#endif /* BRIX_CACHE_GCAS_H */
