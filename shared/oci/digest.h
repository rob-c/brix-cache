/* digest.h — OCI content-digest grammar + hash helpers (phase-104 §0.7.2).
 *
 * WHAT: parse/validate "algorithm:hex" digest strings, compute digests
 *       (whole-buffer and streaming), and compare them in constant time.
 * WHY:  a digest string becomes a path component in the cache key and the
 *       registry store layout, so the grammar IS the traversal defense: a
 *       digest that parses cannot contain '/', '.', or anything but lowercase
 *       hex, by construction. One implementation serves the server classifier,
 *       the push surface and the client tools — three grammars would drift.
 * HOW:  pure C over libc + OpenSSL EVP (the shared-tree hashing precedent,
 *       cvmfs/object/object.c). No allocation; fixed-size out buffers.
 *
 *       The algorithm is carried IN the parsed value, not assumed by the
 *       caller. That is not decoration: the store layout is
 *       `blobs/<alg>/<xx>/<hex>`, so a path cannot be built from a bare hex
 *       string without knowing which algorithm produced it. Every builder
 *       therefore takes a `brix_oci_digest_t`, and the compiler — not a code
 *       review — is what stops a sha512 blob being filed under `sha256/`.
 */
#ifndef BRIX_OCI_DIGEST_H
#define BRIX_OCI_DIGEST_H

#include <stddef.h>

/* The registered algorithms this build can VERIFY. The spec registers both;
 * sha256 is mandatory-to-implement and is what every field client emits, so
 * it stays the producer default (see brix_oci_sha256 below). Anything else on
 * the wire is answered with DIGEST_INVALID rather than trusted. */
typedef enum {
    BRIX_OCI_ALG_SHA256 = 0,
    BRIX_OCI_ALG_SHA512
} brix_oci_alg_t;

/* The enum is dense from 0, so a walker over an algorithm-keyed on-disk
 * layout iterates [0, BRIX_OCI_ALG_COUNT) and asks brix_oci_alg_name() for
 * each directory component — never hardcoding "sha256" and never having to
 * be edited again when a row is added. */
#define BRIX_OCI_ALG_COUNT 2

#define BRIX_OCI_SHA256_HEXLEN 64
#define BRIX_OCI_SHA512_HEXLEN 128
#define BRIX_OCI_HEXLEN_MAX    BRIX_OCI_SHA512_HEXLEN

/* "sha512:" + 128 hex + NUL — the longest string any digest can take. */
#define BRIX_OCI_DIGEST_STRLEN 136
/* "sha256" / "sha512" + NUL. */
#define BRIX_OCI_ALG_NAME_MAX  7

typedef struct {
    char           hex[BRIX_OCI_HEXLEN_MAX + 1];  /* lowercase, NUL-terminated */
    brix_oci_alg_t alg;
} brix_oci_digest_t;

/* Canonical lowercase name ("sha256"/"sha512"); NULL for an unknown enum.
 * This is the string that becomes a directory component, so it is the same
 * one the grammar accepted — never a second spelling. */
const char *brix_oci_alg_name(brix_oci_alg_t alg);

/* Hex width of `alg` (64/128), or 0 for an unknown enum. */
size_t brix_oci_alg_hexlen(brix_oci_alg_t alg);

/* Parse "<alg>:<hex>" from [s, s+n). Rejects unregistered algorithms,
 * uppercase hex, wrong length for the named algorithm, and embedded NUL.
 * 0 ok / -1 invalid. */
int brix_oci_digest_parse(const char *s, size_t n, brix_oci_digest_t *out);

/* Parse a BARE hex span whose algorithm its WIDTH implies — 64 chars is
 * sha256, 128 is sha512, and no two registered algorithms share a width, so
 * the mapping is total and unambiguous. This is what a store whose filenames
 * are bare hex (a layer mark, a roots-ledger entry, a CAS fan-out leaf) reads
 * its own names back with, instead of assuming one algorithm or inventing a
 * second hex check. 0 ok / -1 when no registered width matches or the span is
 * not lowercase hex. */
int brix_oci_digest_parse_hex(const char *hex, size_t n,
                              brix_oci_digest_t *out);

/* Format "<alg>:<hex>" into out[outsz]. Returns bytes written or -1 if the
 * buffer is short (BRIX_OCI_DIGEST_STRLEN always suffices). */
int brix_oci_digest_format(const brix_oci_digest_t *d, char *out, size_t outsz);

/* Constant-time equality (1 equal / 0 not). Timing safety matters on the push
 * surface, where the compared value is attacker-supplied and the reference is
 * a store key. Digests of different algorithms are never equal. */
int brix_oci_digest_eq(const brix_oci_digest_t *a, const brix_oci_digest_t *b);

/* One-shot hash of [data, data+len) under `alg`. 0 ok / -1 (EVP failure). */
int brix_oci_digest_hash(brix_oci_alg_t alg, const void *data, size_t len,
                         brix_oci_digest_t *out);

/* Streaming — hash-on-stream is how every fetched blob is verified without a
 * second read pass. The struct is caller-embedded; the EVP context behind
 * `md` is allocated by init and released by final/abort. */
typedef struct { void *md; int live; brix_oci_alg_t alg; } brix_oci_hash_ctx_t;

int  brix_oci_hash_init(brix_oci_hash_ctx_t *c, brix_oci_alg_t alg);
int  brix_oci_hash_update(brix_oci_hash_ctx_t *c, const void *data, size_t len);
/* Finalize into *out; the ctx is dead afterwards (re-init to reuse). */
int  brix_oci_hash_final(brix_oci_hash_ctx_t *c, brix_oci_digest_t *out);
/* Abandon a live ctx without producing a digest (error paths). */
void brix_oci_hash_abort(brix_oci_hash_ctx_t *c);

/* sha256 shorthands. Everything this project PRODUCES is sha256 — ingest,
 * layout writes, manifest bindings — so those call sites say so by name
 * instead of threading an algorithm they never vary. */
typedef brix_oci_hash_ctx_t brix_oci_sha256_ctx_t;

int  brix_oci_sha256(const void *data, size_t len, brix_oci_digest_t *out);
int  brix_oci_sha256_init(brix_oci_sha256_ctx_t *c);
int  brix_oci_sha256_update(brix_oci_sha256_ctx_t *c, const void *data, size_t len);
int  brix_oci_sha256_final(brix_oci_sha256_ctx_t *c, brix_oci_digest_t *out);
void brix_oci_sha256_abort(brix_oci_sha256_ctx_t *c);

#endif /* BRIX_OCI_DIGEST_H */
