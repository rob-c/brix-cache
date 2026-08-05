/* reflog.h — .cvmfsreflog reader + writer (pure C; phase-96 S10).
 *
 * WHAT: the repository reference log — a SQLite DB at the repo root listing
 *       every root object (catalogs, certificates, history) a revision has
 *       published, the anchor set garbage collection marks from.
 * WHY:  GC must never sweep on an untrusted or absent ref set; publish appends
 *       here, gc reads + prunes here.
 * HOW:  refs(hash TEXT, type INTEGER, timestamp INTEGER) keyed (hash,type) —
 *       the upstream shape. The reflog is UNSIGNED by convention; integrity
 *       comes from the manifest's 'Y' checksum field (sha1 of the file bytes),
 *       which cvmfs_reflog_checksum() computes.
 */
#ifndef BRIX_CVMFS_REFLOG_H
#define BRIX_CVMFS_REFLOG_H

#include <stddef.h>
#include <stdint.h>
#include "cvmfs/grammar/hash.h"

typedef enum {
    CVMFS_REFLOG_CATALOG     = 0,
    CVMFS_REFLOG_CERTIFICATE = 1,
    CVMFS_REFLOG_HISTORY     = 2,
    CVMFS_REFLOG_METAINFO    = 3
} cvmfs_reflog_type_e;

typedef struct cvmfs_reflog_s cvmfs_reflog_t;

/* Open `path`, creating the schema when the file is new. NULL on error. */
cvmfs_reflog_t *cvmfs_reflog_open(const char *path);
/* Commit and close. 0 on success. */
int cvmfs_reflog_close(cvmfs_reflog_t *r);

/* Insert (or refresh the timestamp of) one reference. 0 on success. */
int cvmfs_reflog_add(cvmfs_reflog_t *r, const cvmfs_hash_t *hash,
                     cvmfs_reflog_type_e type, int64_t timestamp);
/* Delete one reference. 0 even when absent. */
int cvmfs_reflog_del(cvmfs_reflog_t *r, const cvmfs_hash_t *hash,
                     cvmfs_reflog_type_e type);

/* Enumerate references of `type` (any type when type < 0), newest first.
 * Returns row count or -1. */
typedef void (*cvmfs_reflog_cb)(const cvmfs_hash_t *hash, cvmfs_reflog_type_e type,
                                int64_t timestamp, void *ud);
int cvmfs_reflog_list(cvmfs_reflog_t *r, int type, cvmfs_reflog_cb cb, void *ud);

/* sha1 of the reflog FILE bytes — the manifest 'Y' value. 0 on success. */
int cvmfs_reflog_checksum(const char *path, cvmfs_hash_t *out);

#endif /* BRIX_CVMFS_REFLOG_H */
