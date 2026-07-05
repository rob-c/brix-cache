/* manifest.h — parse a CVMFS .cvmfspublished manifest (pure C).
 *
 * WHAT: key-value metadata + the exact byte range the signature covers.
 * WHY:  the client must verify + follow the root catalog; the server may
 *       optionally verify what it caches.
 * HOW:  line walk; the signed body is everything up to and including "--\n";
 *       then a hash line, then the raw RSA signature. Pointers alias the
 *       caller's buffer (no allocation).
 */
#ifndef BRIX_CVMFS_MANIFEST_H
#define BRIX_CVMFS_MANIFEST_H

#include <stddef.h>
#include "cvmfs/grammar/hash.h"

typedef struct {
    cvmfs_hash_t         root_catalog;      /* 'C' */
    long                 catalog_size;      /* 'B' */
    cvmfs_hash_t         certificate;       /* 'X' */
    long                 revision;          /* 'S' */
    long                 ttl;               /* 'D' seconds */
    long                 timestamp;         /* 'T' */
    char                 repo_name[256];    /* 'N' */
    const unsigned char *signed_body;       size_t signed_body_len;  /* thru "--\n" */
    cvmfs_hash_t         signed_hash;       /* hash line after "--", parsed */
    const unsigned char *signed_hash_text;  size_t signed_hash_text_len; /* raw ASCII
                                             * of the hash line — this is the exact
                                             * byte range CVMFS RSA-signs */
    const unsigned char *signature;         size_t signature_len;    /* raw RSA sig */
} cvmfs_manifest_t;

/* Parse `buf`/`len`. Returns 0 and fills *out, or -1 on malformed input. */
int cvmfs_manifest_parse(const unsigned char *buf, size_t len, cvmfs_manifest_t *out);

#endif /* BRIX_CVMFS_MANIFEST_H */
