/* admin.h — Stratum-0 repository administration: GC + tags (phase-96 S11/S12).
 *
 * WHAT: reflog-anchored mark&sweep garbage collection of old revisions, and
 *       named-snapshot tags (add / list / rollback) over the manifest 'H'
 *       history object.
 * WHY:  a publish-only Stratum-0 grows without bound; GC reclaims unreachable
 *       CAS objects, tags give operators a safe republish path after a bad
 *       revision (the revision counter never rewinds).
 * HOW:  both rides the publish engine's trust chain — the manifest is
 *       signature-verified before anything is touched, every CAS fetch is
 *       identity-verified, and every mutation ends in the same sign + atomic
 *       manifest swap the publisher uses. GC refuses to run without a
 *       checksum-clean reflog and never sweeps during a transaction.
 */
#ifndef BRIX_CVMFS_ADMIN_H
#define BRIX_CVMFS_ADMIN_H

#include <stddef.h>
#include "cvmfs/history/history.h"

typedef struct {
    const char *repo_dir;
    const char *keys_dir;       /* NULL → <repo_dir>/keys */
    long        keep_n;         /* > 0: keep the newest N catalog revisions */
    long        keep_since;     /* > 0: also keep revisions with ts >= this */
    long        grace_seconds;  /* never sweep objects younger than this */
} cvmfs_gc_opts_t;

typedef struct {
    long kept_revisions;        /* catalog refs retained in the reflog */
    long dropped_revisions;     /* catalog refs pruned from the reflog */
    long swept_objects;         /* CAS files unlinked */
} cvmfs_gc_stats_t;

/* Mark & sweep: keep set = newest keep_n reflog catalog refs (∪ ts >= keep_since
 * ∪ the current manifest root), mark everything reachable from it plus every
 * non-catalog reflog ref, sweep the rest, prune the reflog, refresh 'Y' and
 * re-sign the manifest at the SAME revision. 0 on success, -1 with err set. */
int cvmfs_gc_run(const cvmfs_gc_opts_t *o, cvmfs_gc_stats_t *st,
                 char *err, size_t errlen);

/* Snapshot the current manifest root as tag `name` (insert-or-replace):
 * history DB is CAS-restored (or born), updated, re-stored, and the manifest's
 * 'H' + 'Y' fields re-signed at the same revision. 0/-1. */
int cvmfs_tag_add(const char *repo_dir, const char *keys_dir, const char *name,
                  const char *description, char *err, size_t errlen);

/* Enumerate tags newest-first via `cb`. Returns tag count (0 when the repo has
 * no history object yet) or -1 with err set. */
int cvmfs_tag_list(const char *repo_dir, cvmfs_history_cb cb, void *ud,
                   char *err, size_t errlen);

/* Republish tag `name`'s tree as revision current+1: the tagged catalog is
 * CAS-fetched, its revision/previous_revision properties rewritten, re-stored
 * as a NEW catalog object and swapped in as the manifest root. 0/-1. */
int cvmfs_tag_rollback(const char *repo_dir, const char *keys_dir,
                       const char *name, long *new_revision,
                       char *err, size_t errlen);

#endif /* BRIX_CVMFS_ADMIN_H */
