/* hash.h — CVMFS content-hash parse/format (pure C, no ngx, no alloc).
 *
 * WHAT: parse "<hex>[-algo]" content hashes and build "<2hex>/<rest><suffix>"
 *       object sub-paths.
 * WHY:  CAS identity + cache keying need one canonical hash representation
 *       shared by the client and the server.
 * HOW:  fixed-size struct, no allocation; SHAKE-128 is truncated to 20 bytes
 *       as upstream CVMFS does, so every algo fits the same 20-byte buffer.
 */
#ifndef BRIX_CVMFS_HASH_H
#define BRIX_CVMFS_HASH_H

#include <stddef.h>

typedef enum {
    CVMFS_HASH_SHA1 = 0,
    CVMFS_HASH_RMD160,
    CVMFS_HASH_SHAKE128
} cvmfs_hash_algo_e;

typedef struct {
    cvmfs_hash_algo_e algo;
    unsigned char     bytes[20];
    size_t            len;
} cvmfs_hash_t;

/* Parse "<40hex>", "<40hex>-rmd160" or "<40hex>-shake128". 0 on success. */
int cvmfs_hash_parse(const char *hex, size_t hexlen, cvmfs_hash_t *out);

/* Write "<2hex>/<rest><suffix>" (suffix 0 = none). Returns bytes written or -1. */
int cvmfs_hash_to_object_path(const cvmfs_hash_t *h, char suffix, char *buf, size_t buflen);

/* Write the contiguous hex "<hex><suffix>" (no '/', suffix 0 = none) — the CAS
 * cache-key form. Returns bytes written or -1. */
int cvmfs_hash_to_hex(const cvmfs_hash_t *h, char suffix, char *buf, size_t buflen);

/* Adopt raw digest bytes under a given algo. 0 on success. */
int cvmfs_hash_from_bytes(cvmfs_hash_algo_e a, const unsigned char *b, size_t n, cvmfs_hash_t *out);

/* 1 if equal (same algo + bytes). */
int cvmfs_hash_eq(const cvmfs_hash_t *a, const cvmfs_hash_t *b);

#endif /* BRIX_CVMFS_HASH_H */
