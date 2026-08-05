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

/* ---- the single-object size contract ------------------------------------
 *
 * A CAS object is fetched whole into memory: the compressed bytes land in the
 * fetch scratch, then inflate into a plaintext buffer. Both buffers are sized
 * from the object's plaintext size, which the catalog always knows (file size
 * for a whole-file object, chunk size for a 'P' chunk).
 *
 * CVMFS_OBJECT_MAX_BYTES is the ceiling on that allocation, and it is the
 * SHARED contract between the two sides: the publisher refuses a --chunk-size
 * above it (CVMFS_PUBLISH_CHUNK_CEIL), so it can never emit an object the
 * client cannot land. Raising one without the other reintroduces exactly the
 * failure this constant exists to prevent — a repository whose own client
 * reads it back as EIO.
 */
#define CVMFS_OBJECT_MAX_BYTES     (256u * 1024u * 1024u)

/* Buffer size to use when the plaintext size is not known ahead of the fetch
 * (catalogs reached without a size column). Grown on demand up to the ceiling. */
#define CVMFS_OBJECT_DEFAULT_BYTES (16u * 1024u * 1024u)

/* Worst-case STORED size for `n` plaintext bytes. zlib's compressBound plus
 * slack for the header/trailer: incompressible input (random data, already
 * compressed payloads) deflates to slightly MORE than it started, which is the
 * case that overflows a scratch buffer sized naively at the plaintext size. */
#define CVMFS_OBJECT_STORED_BOUND(n) \
    ((size_t) (n) + ((size_t) (n) >> 12) + ((size_t) (n) >> 14) \
     + ((size_t) (n) >> 25) + 128u)

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
