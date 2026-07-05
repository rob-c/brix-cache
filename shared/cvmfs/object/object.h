/* object.h — CVMFS stored-object decode + integrity verify (pure C).
 *
 * WHAT: turn a fetched, compressed CAS object into verified plaintext bytes.
 * WHY:  the client must never trust a fetched object until its decompressed
 *       content hashes to the name it was fetched under — that hash check is what
 *       makes retry/resume across ANY mirror safe (SP-D fetch orchestrator).
 * HOW:  CVMFS objects are zlib(deflate)-compressed by default (some are stored
 *       uncompressed); we inflate into a caller-sized buffer (the catalog knows
 *       the size) then hash the plaintext with the object's algorithm and compare
 *       to the expected hash. Digests use OpenSSL EVP (plain hashing, unaffected
 *       by the SHA-1 *signature* policy that bites the manifest path).
 */
#ifndef BRIX_CVMFS_OBJECT_H
#define BRIX_CVMFS_OBJECT_H

#include <stddef.h>
#include "cvmfs/grammar/hash.h"

/* Inflate a zlib stream `src`/`srclen` into `dst` (cap `dstcap`); *dstlen gets
 * the plaintext length. Returns 0 on success, -1 on corrupt input / overflow. */
int cvmfs_object_inflate(const unsigned char *src, size_t srclen,
                         unsigned char *dst, size_t dstcap, size_t *dstlen);

/* Compute the content hash of `data`/`len` under `algo` into *out. 0 on success. */
int cvmfs_object_hash(cvmfs_hash_algo_e algo, const unsigned char *data, size_t len,
                      cvmfs_hash_t *out);

/* 1 if hash(`data`, `expected->algo`) == *expected, else 0. */
int cvmfs_object_verify(const unsigned char *data, size_t len, const cvmfs_hash_t *expected);

#endif /* BRIX_CVMFS_OBJECT_H */
