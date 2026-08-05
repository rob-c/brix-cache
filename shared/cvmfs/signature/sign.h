/* sign.h — CVMFS manifest/whitelist SIGNERS (pure C, OpenSSL; phase-96 S0).
 *
 * WHAT: produce the exact byte shapes verify.c accepts — KV body, "--\n"
 *       separator, sha1-hex-of-body hash line, raw RSA-PKCS#1-v1.5 signature
 *       over the printed hash text (no DigestInfo — the upstream convention).
 * WHY:  the publishing plane (repo mkfs / publish / resign) needs the write
 *       half of the trust chain the read stack already pins.
 * HOW:  the body hash covers the body up to but EXCLUDING the "--\n"
 *       separator (stock CVMFS coverage; body_bound_to_hash in verify.c);
 *       manifests sign with the repo CERT key, whitelists with the MASTER key.
 */
#ifndef BRIX_CVMFS_SIGN_H
#define BRIX_CVMFS_SIGN_H

#include <stddef.h>
#include <openssl/evp.h>
#include "cvmfs/grammar/hash.h"

/* Manifest fields to render. history/reflog hashes are optional (len 0 = omit). */
typedef struct {
    cvmfs_hash_t root_catalog;      /* 'C' (required) */
    long         catalog_size;      /* 'B' */
    cvmfs_hash_t certificate;       /* 'X' (required) */
    long         revision;          /* 'S' */
    const char  *fqrn;              /* 'N' */
    long         timestamp;         /* 'T' */
    long         ttl;               /* 'D' seconds */
    cvmfs_hash_t history;           /* 'H' (optional, len 0 = omit) */
    cvmfs_hash_t reflog_checksum;   /* 'Y' (optional, len 0 = omit) */
} cvmfs_manifest_wr_t;

/* Load a PEM private key from `path`. NULL on error; caller EVP_PKEY_free()s. */
EVP_PKEY *cvmfs_sign_load_key(const char *path);

/* Render the manifest KV body (no "--\n") into buf. Emits, in order:
 * C B X S N T D [H] [Y] plus the upstream compatibility fields
 * R (md5 of the root path, constant), G ("yes": GC-capable) and A ("no").
 * Returns body length or -1 on overflow/missing required field. */
int cvmfs_manifest_body(const cvmfs_manifest_wr_t *m, char *buf, size_t cap);

/* Render the whitelist body (no "--\n") in the official shape: 14-digit UTC
 * creation stamp, E<expiry14>, N<fqrn>, one uppercase-colon fingerprint per
 * line. created14 == NULL stamps the current UTC time (production path);
 * passing a fixed stamp keeps test artifacts byte-deterministic.
 * Returns length or -1. */
int cvmfs_whitelist_body(const char *created14, const char *expiry14,
                         const char *fqrn,
                         const char (*fps)[60], size_t nfp, char *buf, size_t cap);

/* Sign `body` (KV lines, NO trailing "--\n"): append "--\n", the lowercase
 * sha1-hex-of-body line, and the RSA signature over that printed hash text.
 * sha1_digestinfo=0 -> raw RSA-PKCS#1-v1.5 (whitelist scheme);
 * sha1_digestinfo=1 -> RSA-PKCS#1-SHA1 DigestInfo (manifest scheme — the only
 * shape the official client accepts for .cvmfspublished). Writes the complete
 * artifact to out. 0 on success. */
int cvmfs_sign_artifact(const unsigned char *body, size_t body_len, EVP_PKEY *key,
                        int sha1_digestinfo,
                        unsigned char *out, size_t outcap, size_t *outlen);

#endif /* BRIX_CVMFS_SIGN_H */
