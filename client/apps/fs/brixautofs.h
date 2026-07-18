/* brixautofs.h — pure core of the CVMFS-brix automount umbrella (no libfuse).
 *
 * WHAT: the FQRN validator, the repo-slot table state machine, and the
 *       CVMFS_REPOSITORIES membership test used by the `brixMount autofs`
 *       umbrella driver (brixautofs.c).
 * WHY:  the umbrella is the security boundary for attacker-chosen lookup
 *       names on /cvmfs — the pure parts live here so the unit test builds
 *       them without libfuse (compile brixautofs.c with -DBRIXAUTOFS_UNIT).
 */
#ifndef BRIXAUTOFS_H
#define BRIXAUTOFS_H

#include <pthread.h>
#include <sys/types.h>

#define BRIXAUTOFS_MAX_REPOS 128
#define BRIXAUTOFS_FQRN_MAX  256    /* fqrn buffer incl. NUL (name <= 255) */

typedef enum {
    BRIXAUTOFS_FREE = 0,
    BRIXAUTOFS_MOUNTING,            /* slot claimed, child mount in flight */
    BRIXAUTOFS_MOUNTED,             /* child mount verified live */
} brixautofs_state_t;

typedef struct {
    char  fqrn[BRIXAUTOFS_FQRN_MAX];
    int   st;                       /* brixautofs_state_t */
    pid_t pid;                      /* child brixMount pid (MOUNTING/MOUNTED) */
} brixautofs_slot_t;

typedef struct {
    brixautofs_slot_t slot[BRIXAUTOFS_MAX_REPOS];
    pthread_mutex_t   mu;
} brixautofs_table_t;

/* Strict FQRN validator — the /cvmfs lookup-name gate. Accepts only
 * `label(.label)+` where each label is 1..63 chars of [a-z0-9-], not starting
 * or ending with '-', total length <= 255. Everything else (traversal, hidden
 * files, editor probes, meta characters, single labels) is rejected. */
int brixautofs_valid_fqrn(const char *name);

/* 1 iff `fqrn` appears in `list` (CVMFS_REPOSITORIES style: ',' / ':' / space
 * separated; empty/NULL list matches nothing). */
int brixautofs_repo_listed(const char *list, const char *fqrn);

/* Table ops. init once; the *_locked ops require t->mu held by the caller. */
void brixautofs_table_init(brixautofs_table_t *t);
int  brixautofs_find_locked(brixautofs_table_t *t, const char *fqrn);   /* idx or -1 */
int  brixautofs_claim_locked(brixautofs_table_t *t, const char *fqrn);  /* -> MOUNTING idx, or -1 full */
void brixautofs_commit_locked(brixautofs_table_t *t, int idx, pid_t pid); /* -> MOUNTED */
void brixautofs_release_locked(brixautofs_table_t *t, int idx);         /* -> FREE */
int  brixautofs_find_pid_locked(brixautofs_table_t *t, pid_t pid);      /* idx or -1 */

#endif /* BRIXAUTOFS_H */
