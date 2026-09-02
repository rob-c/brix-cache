/*
 * sd_batch_types.h - the by-value slot contracts (phase-107 C4 + C6).
 *
 * WHAT: brix_sd_unlink_batch_t, the one value the unlink_many/_cred vtable
 *       slots take: a borrowed window of confined non-directory keys with a
 *       per-key result vector.  And brix_sd_precond_t, the typed publish
 *       precondition staged_commit carries (C6): create-if-absent and
 *       compare-and-publish, expressed once instead of a boolean per driver.
 * WHY:  A DeleteObjects of 1,000 keys over a remote backend was 1,000 signed
 *       round trips whose whole purpose was to avoid exactly that. One batch
 *       value keeps the slot signatures stable and the contract in one place.
 * HOW:  The VFS chunker (vfs_unlink_many.c) fills a window and flushes; a tree
 *       delete batches only WITHIN one directory level (a prefix cannot go
 *       before its children - every driver but mirage has CAP_DIRS, so the
 *       per-level rule IS the rule, not a special case).
 */
#ifndef BRIX_SD_BATCH_TYPES_H
#define BRIX_SD_BATCH_TYPES_H

#include <errno.h>       /* the evaluator's refusal errnos */
#include <stddef.h>
#include <stdio.h>       /* snprintf for the shared etag grammar */
#include <string.h>      /* memcmp */
#include <sys/types.h>   /* off_t */
#include <time.h>        /* time_t */

/* The batch ceiling: no call ever carries more keys than this. The cap bit
 * (BRIX_SD_CAP_BULK_DELETE, "my unlink_many is a real batch, not a loop")
 * decides where the WINDOW COMES FROM, not its size: with the bit, the rmtree
 * walker actively accumulates up to this many keys per flush - buffering is
 * worth it because each flush is one round trip. Without the bit the walker
 * does not accumulate (a looping slot saves no round trips), but a slot a
 * no-bit driver still implements (pblock: one transaction; ceph: one ioctx)
 * is handed the full flat batch by brix_vfs_delete_many, where the client
 * supplied the keys and accumulation cost nothing. */
#define BRIX_SD_BULK_DELETE_WINDOW  1000

/*
 * The batch value.
 *
 *  paths  borrowed, n entries, each already confined by the caller (the slot
 *         never re-resolves), none a directory - directories are removed
 *         singly after their children, outside any window.
 *  n      <= the driver's window; the VFS chunker guarantees it.
 *  errs   caller-allocated, n entries. The slot writes 0 for success and a
 *         positive errno per key. ENOENT is written as ENOENT, never silently
 *         mapped - the CALLER decides idempotency, exactly as the S3
 *         DeleteObjects handler does.
 *  done   number of leading entries the slot actually attempted; a transport
 *         failure at key k sets done = k and the slot returns NGX_ERROR with
 *         errno set, leaving errs[k..n) untouched (the chunker pre-fills them
 *         with ECANCELED so an untried key is never reported as deleted).
 *
 * Slot return: NGX_OK - every key attempted, per-key results in errs (which
 * may still hold failures); NGX_ERROR - the batch itself failed. A NULL slot
 * means the VFS runs the per-key loop; behaviour is identical, only slower.
 */
typedef struct {
    const char *const *paths;
    size_t             n;
    int               *errs;
    size_t             done;
} brix_sd_unlink_batch_t;

/*
 * The publish precondition (phase-107 C6) — the second argument of the
 * staged_commit slot, replacing the old `int noreplace` boolean the wave-7 ABI
 * change retired (a boolean has nowhere to put an entity tag).
 *
 * kind == 0 is NONE, so a zeroed struct — and a NULL pointer, which every
 * caller with no condition passes — is today's unconditional replace: the same
 * fail-safe-by-zero discipline the mutation policy uses, applied to a
 * different question. A caller who forgets to fill the struct gets the OLD
 * semantics, never an accidental refusal.
 *
 * Refusals (slot returns NGX_ERROR):
 *   EEXIST     ABSENT and the target exists      -> kXR_ItExists / 412
 *   ECANCELED  MATCH_* and the compare failed    -> 412 Precondition Failed
 *   ENOTSUP    the driver cannot evaluate this kind at all; there is no
 *              honest emulation, so the VFS refuses rather than pretending
 *
 * etag is BORROWED (pointer + length, not copied; the caller keeps it alive
 * across the call — it is bytes+len rather than ngx_str_t so this header stays
 * ngx-free for the libxrdproto plane, like the batch value above). The tag
 * grammar is the shared weak "mtime-size" form of core/http/etag.h unless the
 * driver's own storage carries a native tag (S3: the real ETag header).
 *
 * atomic is an OUTPUT: the slot sets it when the decision was made AT the
 * storage and could not have raced (BRIX_SD_CAP_PRECOND advertises the same
 * property statically; the field reports it per call, because on `http` it is
 * a runtime fact about the origin, not a compile-time fact about the driver).
 * The protocol layer must not claim RFC 7232 semantics when it is 0. The
 * parameter is therefore non-const by contract — the OUT bit is the reason.
 * Set on REFUSALS too: a 412 the origin answered, an EEXIST that
 * RENAME_NOREPLACE raised, or a verdict reached inside pblock's transaction
 * is a storage-decided refusal, and the C6 advisory metric
 * (brix_vfs_precond_advisory_total) keys on this bit after a failed commit —
 * a refusal that leaves it 0 was a check-then-act compare.
 */
typedef enum {
    BRIX_SD_PRECOND_NONE = 0,      /* replace unconditionally            */
    BRIX_SD_PRECOND_ABSENT,        /* create-if-absent (the old noreplace) */
    BRIX_SD_PRECOND_MATCH_ETAG,    /* replace iff the entity tag matches */
    BRIX_SD_PRECOND_MATCH_META     /* replace iff (size, mtime) matches  */
} brix_sd_precond_kind_t;

typedef struct {
    brix_sd_precond_kind_t  kind;
    const char             *etag;      /* MATCH_ETAG only; borrowed         */
    size_t                  etag_len;
    off_t                   size;      /* MATCH_META only                   */
    time_t                  mtime;     /* MATCH_META only                   */
    unsigned                atomic:1;  /* OUT: storage decided, atomically  */
} brix_sd_precond_t;

/* True when `pre` asks for create-if-absent — the one question the pre-C6
 * boolean could express; drivers that only support ABSENT key on this. */
#define brix_sd_precond_absent(pre)     ((pre) != NULL && (pre)->kind == BRIX_SD_PRECOND_ABSENT)

/* Evaluate a MATCH_* precondition against the target's (size, mtime) — the
 * shared body for every stat-grammar driver (posix, and the VFS's non-driver
 * compat arm) so the etag comparison never forks.  MATCH_ETAG compares the
 * shared "mtime-size" tag of core/http/etag.h (hex mtime, hex size, quoted),
 * honouring RFC 7232 weak comparison: an optional leading W/ on the caller's
 * tag is ignored.  MATCH_META compares the fields directly.  Returns 0 when
 * the precondition holds, -1 with errno = ECANCELED when it does not, and -1
 * with errno = ENOTSUP for a kind this evaluator does not know (a new enum
 * member must be taught here explicitly, never silently passed).  NONE and
 * ABSENT are not questions about (size, mtime) and are the caller's job. */
static inline int
brix_sd_precond_eval_stat(const brix_sd_precond_t *pre, off_t size,
    time_t mtime)
{
    if (pre->kind == BRIX_SD_PRECOND_MATCH_META) {
        if (pre->size == size && pre->mtime == mtime) {
            return 0;
        }
        errno = ECANCELED;
        return -1;
    }
    if (pre->kind == BRIX_SD_PRECOND_MATCH_ETAG) {
        char        tag[48];
        const char *want = pre->etag;
        size_t      want_len = pre->etag_len;
        int         n;

        if (want != NULL && want_len > 2
            && want[0] == 'W' && want[1] == '/')
        {
            want += 2;                     /* RFC 7232 §2.3.2 weak comparison */
            want_len -= 2;
        }
        n = snprintf(tag, sizeof(tag), "\"%lx-%llx\"",
                     (unsigned long) mtime, (unsigned long long) size);
        if (want != NULL && n > 0 && (size_t) n == want_len
            && memcmp(tag, want, want_len) == 0)
        {
            return 0;
        }
        errno = ECANCELED;
        return -1;
    }
    errno = ENOTSUP;
    return -1;
}

#endif /* BRIX_SD_BATCH_TYPES_H */
