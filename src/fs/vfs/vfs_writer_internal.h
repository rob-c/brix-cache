#ifndef BRIX_VFS_WRITER_INTERNAL_H
#define BRIX_VFS_WRITER_INTERNAL_H

/*
 * vfs_writer_internal.h — shared internals of the unified write session
 * (vfs_writer.c + vfs_writer_spill.c). Phase-107 C1.
 *
 * WHAT: The writer's mode machine, the spill scratch state, and the session
 *       struct both translation units mutate, plus the spill
 *       transition/put/drain/discard entry points vfs_writer.c dispatches to.
 * WHY:  vfs_writer.c sits near the 600-LOC ceiling and the spill mode is a
 *       self-contained concern (scratch lifecycle, extent bookkeeping, the
 *       sequential drain), so phase-107 W2 lands it in its own unit; the
 *       session struct must be shared, not duplicated, so it moves here.
 * HOW:  Nothing in this header is public API — protocols include
 *       fs/vfs/vfs_ops.h and see only the opaque brix_vfs_writer_t.
 */

#include "vfs_internal.h"
#include "core/compat/wverify.h"

/* The session's write-mechanics state machine (phase-107 C1 §4). RANDOM vs
 * SEQUENTIAL is chosen at open from the backend's CAP_RANDOM_WRITE;
 * SEQUENTIAL promotes ONE WAY to SPILL on the first out-of-order extent (or
 * on BRIX_VFS_WRITER_O_UNORDERED at open), because once bytes land in the
 * scratch it is the authority on the object's contents; SPILL degrades to
 * FAILED when the scratch cannot hold the object (ENOSPC / spill_max). No
 * state is ever re-entered, and RANDOM never spills — it has no ordering
 * constraint to violate. */
typedef enum {
    BRIX_VFS_WRITER_RANDOM = 0,   /* in-place handle, any offset            */
    BRIX_VFS_WRITER_SEQUENTIAL,   /* staged upload, cursor-ordered          */
    BRIX_VFS_WRITER_SPILL,        /* local scratch absorbs any offset       */
    BRIX_VFS_WRITER_FAILED        /* scratch exhausted; ENOSPC until finish */
} brix_vfs_writer_mode_t;

/* One disjoint byte range landed in the scratch, [start, end) in OBJECT
 * offsets. The set stays sorted and coalesced so a mostly-sequential stream
 * with occasional reordering costs a handful of entries. */
typedef struct {
    off_t  start;
    off_t  end;
} brix_vfs_spill_ext_t;

/* Spill scratch (phase-107 C1, Appendix A.9): one sparse POSIX temp under the
 * export's spill root — service storage, never the export namespace. File
 * offsets are object offsets minus `base`: bytes below `base` were already
 * streamed into the driver's staged session before the promotion and can
 * never be patched again. The extent set is what makes the drain honest — a
 * byte the client never sent is refused, not zero-filled (the filesystem
 * zero-fills sub-block holes silently, so SEEK_HOLE cannot detect them). */
typedef struct {
    ngx_fd_t              fd;         /* scratch temp (NGX_INVALID_FILE = none) */
    u_char               *path;       /* pool-owned; unlinked on discard        */
    off_t                 base;       /* first object byte the spill owns       */
    off_t                 high_water; /* highest object offset+len seen         */
    off_t                 written;    /* bytes landed (metrics/diagnostics)     */
    off_t                 max;        /* cap on (high_water - base); 0 = none   */
    brix_vfs_spill_ext_t *ext;        /* sorted disjoint coverage set           */
    ngx_uint_t            n_ext;
    ngx_uint_t            ext_cap;
} brix_vfs_spill_t;

struct brix_vfs_writer_s {
    brix_vfs_ctx_t    *ctx;            /* pool-owned deep clone (self-contained) */
    ngx_pool_t        *pool;
    ngx_log_t         *log;
    brix_vfs_file_t   *fh;             /* random-write path (else NULL)          */
    brix_vfs_staged_t *st;             /* staged-upload path (else NULL)         */
    brix_wverify_t    *wv;             /* verify accumulator (NULL when !verify) */
    off_t              staged_cursor;  /* next expected offset on the staged path*/
    off_t              written;        /* total bytes written                    */
    brix_vfs_spill_t   spill;          /* SPILL-mode scratch (phase-107 C1)      */
    /* Phase-105: the endpoint's mutation policy, copied at open. A write
     * session outlives the request that opened it, so every writer gate
     * decides from this copy and never from w->ctx being re-read. */
    brix_vfs_mutation_policy_t mutation_policy;
    brix_vfs_writer_mode_t     mode;
    unsigned           verify:1;
    unsigned           finished:1;     /* commit or abort has run                */
};

/* T1 — promote a SEQUENTIAL session to SPILL for a write of `len` bytes at
 * object offset `off` (len 0 = the BRIX_VFS_WRITER_O_UNORDERED declaration at
 * open). Creates the scratch under the export's spill root (brix_vfs_spill_path,
 * falling back to brix_stage_dir). NGX_OK with w->mode == SPILL on success.
 * NGX_ERROR with errno = EINVAL when `off` rewinds below the already-staged
 * prefix (unservable — the session STAYS SEQUENTIAL so an in-order
 * continuation still succeeds), or ENOSPC when no spill root is configured /
 * scratch creation fails (stays SEQUENTIAL) or the triggering extent already
 * exceeds spill_max (T4: mode -> FAILED, staged session aborted). */
ngx_int_t brix_vfs_writer_spill_enter(brix_vfs_writer_t *w, off_t off,
    size_t len);

/* Land one extent in the scratch. EINVAL for an offset below spill.base or an
 * overlap with bytes already landed (double-written bytes would also poison
 * the verify CRC); ENOSPC past spill_max, on a failed scratch write, or when
 * the extent set outgrows its ceiling — the capacity cases are T4 and move
 * the session to FAILED. */
ngx_int_t brix_vfs_writer_spill_put(brix_vfs_writer_t *w, const void *buf,
    size_t len, off_t off);

/* T2 — stream the scratch [base, high_water) sequentially into the session's
 * staged upload. Refuses (EINVAL) a scratch whose extent set does not cover
 * the span exactly: a hole is a client error, never zero-filled. Does NOT
 * commit or discard — the caller owns the commit ordering (drain ->
 * staged_commit -> discard, so a crash mid-publish leaves the bytes). */
ngx_int_t brix_vfs_writer_spill_drain(brix_vfs_writer_t *w);

/* Unlink + close the scratch and drop the active-spill gauge. Idempotent,
 * safe on a session that never spilled. */
void brix_vfs_writer_spill_discard(brix_vfs_writer_t *w);

#endif /* BRIX_VFS_WRITER_INTERNAL_H */
