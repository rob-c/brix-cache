/* history.h — CVMFS tag/history database (pure C; phase-96 S12).
 *
 * WHAT: the named-snapshot database the manifest's 'H' field points at — an
 *       'H'-suffix CAS object holding tags(name → root hash, revision, time).
 * WHY:  tags make a Stratum-0 operationally usable: `brixcvmfs tag rollback`
 *       republishes a tagged root catalog as a NEW revision after a bad
 *       publish (the revision counter never rewinds).
 * HOW:  plain SQLite, upstream table shape; the DB file is written locally,
 *       then zlib-compressed and CAS-stored like every other object, so tag
 *       tamper is caught by the ordinary object hash verify.
 */
#ifndef BRIX_CVMFS_HISTORY_H
#define BRIX_CVMFS_HISTORY_H

#include <stddef.h>
#include <stdint.h>
#include "cvmfs/grammar/hash.h"

typedef struct cvmfs_history_s cvmfs_history_t;

typedef struct {
    char         name[128];
    cvmfs_hash_t root_hash;
    long         revision;
    int64_t      timestamp;
    char         description[256];
} cvmfs_history_tag_t;

/* Open `path` (creating the schema when new; `fqrn` recorded on create;
 * pass NULL fqrn when opening an existing DB). NULL on error. */
cvmfs_history_t *cvmfs_history_open(const char *path, const char *fqrn);
int cvmfs_history_close(cvmfs_history_t *h);

/* Insert or replace a tag. 0 on success. */
int cvmfs_history_tag_add(cvmfs_history_t *h, const cvmfs_history_tag_t *tag);
/* Fetch tag `name`. 1 found, 0 absent, -1 error. */
int cvmfs_history_tag_get(cvmfs_history_t *h, const char *name, cvmfs_history_tag_t *out);
/* Delete tag `name`. 0 even when absent. */
int cvmfs_history_tag_del(cvmfs_history_t *h, const char *name);

/* Enumerate tags, newest first. Returns tag count or -1. */
typedef void (*cvmfs_history_cb)(const cvmfs_history_tag_t *tag, void *ud);
int cvmfs_history_list(cvmfs_history_t *h, cvmfs_history_cb cb, void *ud);

#endif /* BRIX_CVMFS_HISTORY_H */
