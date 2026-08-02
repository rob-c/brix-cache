/* xorf.h — negative-lookup membership filter (phase-87 G1, pure C, no ngx).
 *
 * WHAT: an 8-bit-fingerprint xor filter over a repo revision's path-set with a
 *       root-hash-bound, checksummed serialized form. Query answers "definitely
 *       absent" (safe in-process ENOENT) or "maybe present" (fall through to
 *       the verified catalog lookup).
 * WHY:  build systems and import machinery stat() torrents of paths that do
 *       not exist; without a filter every miss is a catalog consultation. An
 *       xor filter has NO false negatives, so the ENOENT short-circuit can
 *       never hide a real path — a ~1/256 false positive just costs the normal
 *       lookup it would have done anyway.
 * HOW:  classic 3-block xor-8 construction (Graf/Lemire): each key maps to one
 *       cell per block plus an 8-bit fingerprint; build peels cells of degree 1
 *       until every key is placed (retrying with a fresh seed on the rare
 *       failure), query xors the key's three cells against its fingerprint.
 *       The serialized image binds the root-catalog hash it was built for and
 *       carries an FNV-1a64 checksum so a tampered/bit-flipped sidecar or
 *       download fails closed (rejected, caller falls back to live lookups).
 */
#ifndef BRIX_CVMFS_XORF_H
#define BRIX_CVMFS_XORF_H

#include "cvmfs/grammar/hash.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t       seed;        /* construction seed the build settled on */
    uint32_t       block_len;   /* cells per block; fingerprint array = 3x this */
    uint32_t       nkeys;       /* keys the filter was built over (info only) */
    unsigned char *fp;          /* 3*block_len fingerprints, heap-owned */
} cvmfs_xorf_t;

/* Serialized image: 44-byte header + fingerprints + trailing 8-byte checksum. */
#define CVMFS_XORF_MAGIC       "BXF1"
#define CVMFS_XORF_HEADER_LEN  44u
#define CVMFS_XORF_MAX_KEYS    (64u * 1024u * 1024u)   /* sanity cap, ~64M paths */

/* Map a catalog-relative path (e.g. "/dir/leaf", root "") to its filter key. */
uint64_t cvmfs_xorf_key(const char *path);

/* Build the filter over `n` keys (duplicates tolerated — deduped internally).
 * `keys` is scrambled by the dedup sort. 0 on success, -1 on alloc/degenerate
 * failure; on failure `f` is left empty (query returns "maybe"). */
int cvmfs_xorf_build(cvmfs_xorf_t *f, uint64_t *keys, size_t n);

/* 0 = definitely NOT a member; 1 = maybe a member (or filter empty/unbuilt). */
int cvmfs_xorf_query(const cvmfs_xorf_t *f, uint64_t key);

/* Total serialized size (header + fingerprints + checksum) of a built filter. */
size_t cvmfs_xorf_size(const cvmfs_xorf_t *f);

/* Serialize `f`, binding `root` (the root-catalog hash the path-set came from).
 * 0 on success, -1 if `out` is too small (need cvmfs_xorf_size()). */
int cvmfs_xorf_serialize(const cvmfs_xorf_t *f, const cvmfs_hash_t *root,
                         unsigned char *out, size_t cap, size_t *outlen);

/* Parse + integrity-check a serialized image into `f` (heap copy) and return
 * the bound root hash in `root`. 0 on success; -1 on ANY defect (bad magic,
 * truncation, checksum mismatch, absurd geometry) — fail closed, `f` empty. */
int cvmfs_xorf_deserialize(cvmfs_xorf_t *f, cvmfs_hash_t *root,
                           const unsigned char *in, size_t len);

/* Free the fingerprint array and zero the struct (safe on an empty filter). */
void cvmfs_xorf_reset(cvmfs_xorf_t *f);

#endif /* BRIX_CVMFS_XORF_H */
