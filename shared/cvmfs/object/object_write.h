/* object_write.h — CVMFS CAS object WRITER (pure C; phase-96 S2).
 *
 * WHAT: compress → hash the STORED bytes → atomically place an object at
 *       data/<2hex>/<rest><suffix> inside a repository store.
 * WHY:  the publishing plane's one write path for content, catalogs, certs,
 *       chunks and history objects; the reader (object.c) is the oracle.
 * HOW:  identity is the hash of the stored (compressed) form — the exact rule
 *       object.c/fetch.c verify by. I/O rides brix_cas_store (O_EXCL temp +
 *       fsync + rename; immutable-put), never fresh raw syscalls.
 */
#ifndef BRIX_CVMFS_OBJECT_WRITE_H
#define BRIX_CVMFS_OBJECT_WRITE_H

#include <stddef.h>
#include "cvmfs/grammar/hash.h"
#include "cache/cas_store.h"

typedef struct {
    brix_cas_store_t cas;           /* rooted at <repo_dir>/data */
} cvmfs_objstore_t;

/* Bind to (creating if needed) `<repo_dir>/data`. 0 on success. */
int  cvmfs_objstore_open(cvmfs_objstore_t *s, const char *repo_dir);
void cvmfs_objstore_close(cvmfs_objstore_t *s);

/* Store `plain` as a CAS object: zlib-deflate (or verbatim when compress=0),
 * sha1 the stored bytes into *out, place at data/<2>/<rest><suffix>
 * (suffix 0 = content, 'C' catalog, 'X' cert, 'P' chunk, 'H' history).
 * *stored_len (optional) gets the stored byte count. 0 on success. */
int cvmfs_object_store(cvmfs_objstore_t *s, const unsigned char *plain, size_t len,
                       char suffix, int compress, cvmfs_hash_t *out, size_t *stored_len);

/* 1 if the object `hash`+`suffix` exists in the store. */
int cvmfs_object_present(cvmfs_objstore_t *s, const cvmfs_hash_t *hash, char suffix);

/* Read a stored object verbatim (as served) into `out`. Returns the stored
 * length, or -1 on absence/overflow. */
long cvmfs_object_read_stored(cvmfs_objstore_t *s, const cvmfs_hash_t *hash, char suffix,
                              unsigned char *out, size_t outcap);

/* Delete object `hash`+`suffix` (GC sweep). 0 on success or absence. */
int cvmfs_object_delete(cvmfs_objstore_t *s, const cvmfs_hash_t *hash, char suffix);

#endif /* BRIX_CVMFS_OBJECT_WRITE_H */
