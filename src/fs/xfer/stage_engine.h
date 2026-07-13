#ifndef BRIX_FS_XFER_STAGE_ENGINE_H
#define BRIX_FS_XFER_STAGE_ENGINE_H

/*
 * stage_engine.h - the one async-staging engine (phase-64 P4/P5/P6, section 11).
 *
 * WHAT: A single durable-transfer front door, brix_stage_submit(), shared by
 *       every async data-movement path in the storage stack: a cache miss-fill of
 *       a nearline (tape) backend (RECALL), a write-stage flush / tape migrate
 *       (FLUSH), a client-body upload into the stage store (UPLOAD), and an S3
 *       multipart assembly (MULTIPART). One queue, one waiter, one byte mover, one
 *       audit ledger - for all four kinds.
 *
 * WHY:  Before phase-64 the same "move bytes from A to B durably, possibly async,
 *       and wake a parked open when done" logic was re-implemented five times
 *       (the POSC upload stage, vfs_scratch, S3 multipart, writethrough flush, the
 *       FRM tape queue). P5 folds them into ONE engine; the src/dst become SD
 *       instances (any driver) instead of FRM's local-path/stagecmd model, so the
 *       same engine moves bytes between any two tiers. The sd_stage / sd_cache
 *       decorators and the (future) frm nearline driver are its only callers.
 *
 * HOW:  brix_stage_submit(kind, src, src_key, dst, dst_key, opts) runs the
 *       generic promote loop - open `src` for read, staged_open `dst`, pread ->
 *       staged_write -> staged_commit - and books one brix_xfer_finish() audit
 *       line on the terminal state. A synchronous submit runs the mover inline and
 *       returns ""; an async submit parks the open on a durable request id.
 *
 *       SP1 lands this seam with the inline mover fully working; the durable queue
 *       + waiter + restart-reconcile are EXTRACTED from src/frm/ in SP4 (section
 *       13b) and attach behind this same surface without touching a caller. Until
 *       then an async submit degrades to an inline move (honest: no durability is
 *       claimed that is not yet implemented), and the scheduler/reconcile entry
 *       points are no-ops. See docs/refactor/phase-64-fully-tiered-composable-
 *       storage.md (section 11, Appendix H/I).
 */

#include <ngx_core.h>

#include "fs/backend/sd.h"   /* brix_sd_instance_t */

/*
 * Per-user owner identity embedded in the durable request record.
 *
 * WHAT: A wire-stable POD (no bitfields, no pointers, no padding hazards) that
 *       captures the credential key, canonical principal, credential directory,
 *       and deny-on-missing flag at submit time so a detached / async write-back
 *       flush — possibly after a crash and restart — can re-resolve and
 *       authenticate to the origin as the ORIGINAL user, rather than falling back
 *       silently to the service credential.
 *
 * WHY:  The flush thread runs outside the request context.  Without a persisted
 *       identity the engine has no choice but to flush as the service user, which
 *       can break per-user quota / audit / access-control on the backend.
 *       Persisting key + dir lets brix_sd_ucred_resolve() recheck expiry at flush
 *       time; setting deny=1 causes a hard EACCES / BRIX_XFER_DENIED when the
 *       per-user credential is absent or expired rather than silently promoting as
 *       the service identity.
 *
 * HOW:  This struct is memcpy'd verbatim into brix_sreq_t (the on-disk journal
 *       record) as the FINAL member.  NO bitfields, NO pointers, NO embedded
 *       structs with alignment holes — the layout must be byte-stable across
 *       builds.  Field sizes match BRIX_UCRED_{KEY,PRINC,PATH}_MAX constants from
 *       ucred.h (128 / 512 / 1024) so there is no truncation risk at assignment.
 */
typedef struct {
    char    key[128];       /* filesystem-safe credential filename stem (ucred_key) */
    char    principal[512]; /* canonical principal string (DN or JWT sub)           */
    char    dir[1024];      /* credential directory path (brix_sd_ucred_dir)        */
    uint8_t deny;           /* 1 = EACCES on missing/expired cred; 0 = service-cred */
} brix_stage_cred_t;

/* The four async-staging kinds (Appendix I). Values are stable wire identities so
 * a durable request record (SP4) survives a restart; they line up 1:1 with the
 * legacy frm_xfer_kind_t the engine subsumes. */
typedef enum {
    BRIX_STAGE_RECALL    = 0,   /* nearline backend -> cache store   (data in)  */
    BRIX_STAGE_FLUSH     = 1,   /* stage store -> backend            (data out) */
    BRIX_STAGE_UPLOAD    = 2,   /* client body -> stage store        (data in)  */
    BRIX_STAGE_MULTIPART = 3    /* S3 part(s) -> stage store         (data in)  */
} brix_stage_kind_t;

/* Durable request lifecycle (Appendix I). SP1 only ever transits QUEUED->DONE /
 * FAILED inline; the persisted INFLIGHT/EXPIRED transitions arrive with the SP4
 * durable queue. */
typedef enum {
    BRIX_SREQ_QUEUED   = 0,
    BRIX_SREQ_INFLIGHT = 1,
    BRIX_SREQ_DONE     = 2,
    BRIX_SREQ_FAILED   = 3,
    BRIX_SREQ_EXPIRED  = 4
} brix_sreq_state_t;

/* The durable on-disk request record (Appendix I; persisted by the SP4 queue).
 * Carried in the header now so the seam vocabulary is stable - exactly the
 * "full vocabulary up front, land it incrementally" pattern xfer.h uses. One per
 * transfer; the instance is rebuilt from {driver,key} on replay. */
typedef struct {
    char                 reqid[40];        /* minted request id (NUL-terminated)     */
    brix_stage_kind_t  kind;
    brix_sreq_state_t  state;
    char                 src_driver[16];
    char                 src_key[1024];
    char                 dst_driver[16];
    char                 dst_key[1024];
    char                 export_root[1024]; /* anchor to rebuild both tiers (SP4)    */
    uint16_t             open_options;     /* echoed to a parked open on wake         */
    uint64_t             size_hint;
    uint64_t             bytes_done;        /* resume cursor (mover writes it through) */
    int64_t              enqueued_at;
    int64_t              started_at;
    int64_t              finished_at;
    uint32_t             attempts;
    int32_t              last_errno;
    /* APPEND-ONLY: cred MUST remain the final member.  offsetof(brix_sreq_t, cred)
     * is the legacy pre-cred record size; brix_sreq_decode uses that identity to
     * replay old journal records with a zeroed (service-credential) cred. */
    brix_stage_cred_t    cred;
} brix_sreq_t;

/* Per-submit options. `async` requests park-and-defer (SP4); `conn` is the client
 * connection a parked open is woken on; `open_options` is echoed back to it;
 * `ttl_ms` bounds how long a parked open waits (0 = engine default).
 * `cred` carries the owner identity for async flushes (NULL = service credential). */
typedef struct {
    unsigned                  async:1;
    off_t                     size_hint;
    uint16_t                  open_options;
    ngx_connection_t         *conn;
    ngx_msec_t                ttl_ms;
    const char               *export_root; /* anchor to rebuild both tiers on reconcile */
    const brix_stage_cred_t  *cred;        /* per-user identity to persist in the record */
} brix_stage_opts_t;

/* The durable queue handle (per export; SP4 owns its storage). Opaque here. */
typedef struct brix_stage_queue_s brix_stage_queue_t;

/*
 * Enqueue a durable transfer of the whole object `src_key` on instance `src` to
 * `dst_key` on instance `dst`, of `kind`. The generic promote-loop mover drives
 * it. Returns a stable request id (a NUL-terminated string the caller parks a
 * stalled open on) when the transfer was deferred, or "" (empty) when it ran
 * inline to completion. Returns NULL only on a bad argument.
 *
 * SP1: a synchronous submit (opts NULL or opts->async == 0) runs the mover inline
 * and returns ""; an async submit currently also runs inline (durability is SP4)
 * and returns "". The contract - "" means done, non-empty means park - is already
 * the stable one callers code against.
 */
const char *brix_stage_submit(brix_stage_kind_t kind,
    brix_sd_instance_t *src, const char *src_key,
    brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_opts_t *opts);

/*
 * Run a transfer INLINE with an explicit per-user credential.
 *
 * WHAT: Runs the mover inline (same as brix_stage_run_inline) but threads the
 *       optional `cred` through to the destination staged_open so the backend
 *       driver presents the per-user x509 proxy rather than the service credential.
 *
 * WHY:  The staged_commit and reflush paths both need to carry the owner identity
 *       down to the byte mover; a separate entry point lets callers that already
 *       hold a resolved credential avoid a second key lookup while keeping the
 *       zero-cred path (brix_stage_run_inline) unchanged for callers that don't.
 *
 * HOW:  Validates arguments, then calls stage_engine_run with the cred pointer.
 *       Returns NGX_OK on success, NGX_ERROR on argument error or transfer failure
 *       (errno set).  A NULL cred is the service-credential path.
 */
ngx_int_t brix_stage_run_inline_cred(brix_stage_kind_t kind,
    brix_sd_instance_t *src, const char *src_key,
    brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_cred_t *cred);

/*
 * Run a transfer INLINE and return its terminal result - the synchronous path a
 * caller uses when it must know the outcome now (e.g. a sync stage-flush commit).
 * Same generic mover and audit line as brix_stage_submit; the difference is the
 * return convention: NGX_OK when the object is durably published on `dst`, else
 * NGX_ERROR (errno set). The async/park path (brix_stage_submit) is for when the
 * caller can defer and be woken (SP4).
 * One-line wrapper around brix_stage_run_inline_cred with cred=NULL (service cred).
 */
ngx_int_t brix_stage_run_inline(brix_stage_kind_t kind,
    brix_sd_instance_t *src, const char *src_key,
    brix_sd_instance_t *dst, const char *dst_key);

/*
 * Decode one durable request record from a raw buffer with size-tolerance.
 *
 * WHAT: Returns NGX_OK with *out filled when n == sizeof(brix_sreq_t) (current
 *       full record) or n == offsetof(brix_sreq_t, cred) (legacy pre-cred record,
 *       which yields a zeroed cred = service-credential flush).  Returns NGX_ERROR
 *       for any other n (corrupt or from an incompatible future version).
 *
 * WHY:  brix_sreq_t grew a trailing brix_stage_cred_t; journals written before
 *       the upgrade must replay without data loss.  The zeroed-cred path preserves
 *       the pre-feature semantics: flush under the service identity.
 *
 * HOW:  ngx_memzero + ngx_memcpy(out, buf, n) — the memzero ensures the cred
 *       fields are zero when a legacy-size record is decoded.
 */
ngx_int_t brix_sreq_decode(const void *buf, size_t n, brix_sreq_t *out);

/* Initialise the engine's durable journal directory for this worker (SP4). A
 * NULL/empty dir keeps the async queue in-memory only (no crash recovery). */
void brix_stage_engine_init(const char *journal_dir);

/*
 * Dead-letter cap constants for deny-mode flush retry bounding (Task 4).
 *
 * WHAT: After BRIX_STAGE_DENY_MAX_ATTEMPTS denied flushes, or when the record
 *       has been in the active journal for more than BRIX_STAGE_DENY_MAX_AGE_SEC
 *       seconds and a flush is still denied, the record is moved to the
 *       deadletter/ subdirectory and the scheduler / reconcile stop re-driving it.
 *
 * WHY:  A BRIX_XFER_DENIED result means the per-user credential is permanently
 *       missing or expired in deny mode.  Without a cap the scheduler tick and
 *       restart-reconcile retry the same record forever.  Dead-lettering stops
 *       the loop while preserving the stage copy for operator recovery.
 */
#define BRIX_STAGE_DENY_MAX_ATTEMPTS 5
#define BRIX_STAGE_DENY_MAX_AGE_SEC  (24 * 3600)

/*
 * Evaluate the dead-letter cap for a permanently denied flush.
 *
 * WHAT: Increments rec->attempts, re-persists the updated record to the active
 *       journal slot (via journal_dir/<reqid>.req), then checks whether the
 *       attempt cap or age cap has been reached.  On cap, moves the active
 *       record to <journal_dir>/deadletter/<reqid>.req, emits NGX_LOG_ERR, and
 *       returns 1 (stop re-driving).  Returns 0 when below both caps.
 *
 * WHY:  Shared by stage_complete (BRIX_XFER_DENIED terminal from the scheduler/
 *       thread path) and stage_reconcile_one (EACCES + deny cred from reflush),
 *       so the cap is enforced consistently, including across restarts.
 *
 * HOW:  journal_dir is passed explicitly (rather than using the module-static
 *       stage_journal_dir) so the function is directly unit-testable.  rec is
 *       modified in-place (attempts incremented). */
int stage_deny_terminal(const char *journal_dir, const char *reqid,
    brix_sreq_t *rec, ngx_log_t *log);

/* Per-worker timer hook: drain the deferred (async) queue, running each mover and
 * dropping a completed FLUSH's stage copy (SP4). Bounded per tick. */
void brix_stage_scheduler_tick(void);

/* Restart replay: re-submit every in-flight durable request so no transfer is
 * lost across a crash (SP4). SP1 no-op. */
void brix_stage_reconcile(brix_stage_queue_t *queue);

/* Human string for a kind (audit line + tests). */
const char *brix_stage_kind_str(brix_stage_kind_t kind);

#endif /* BRIX_FS_XFER_STAGE_ENGINE_H */
