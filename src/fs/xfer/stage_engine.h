#ifndef XROOTD_FS_XFER_STAGE_ENGINE_H
#define XROOTD_FS_XFER_STAGE_ENGINE_H

/*
 * stage_engine.h - the one async-staging engine (phase-64 P4/P5/P6, section 11).
 *
 * WHAT: A single durable-transfer front door, xrootd_stage_submit(), shared by
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
 * HOW:  xrootd_stage_submit(kind, src, src_key, dst, dst_key, opts) runs the
 *       generic promote loop - open `src` for read, staged_open `dst`, pread ->
 *       staged_write -> staged_commit - and books one xrootd_xfer_finish() audit
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

#include "fs/backend/sd.h"   /* xrootd_sd_instance_t */

/* The four async-staging kinds (Appendix I). Values are stable wire identities so
 * a durable request record (SP4) survives a restart; they line up 1:1 with the
 * legacy frm_xfer_kind_t the engine subsumes. */
typedef enum {
    XROOTD_STAGE_RECALL    = 0,   /* nearline backend -> cache store   (data in)  */
    XROOTD_STAGE_FLUSH     = 1,   /* stage store -> backend            (data out) */
    XROOTD_STAGE_UPLOAD    = 2,   /* client body -> stage store        (data in)  */
    XROOTD_STAGE_MULTIPART = 3    /* S3 part(s) -> stage store         (data in)  */
} xrootd_stage_kind_t;

/* Durable request lifecycle (Appendix I). SP1 only ever transits QUEUED->DONE /
 * FAILED inline; the persisted INFLIGHT/EXPIRED transitions arrive with the SP4
 * durable queue. */
typedef enum {
    XROOTD_SREQ_QUEUED   = 0,
    XROOTD_SREQ_INFLIGHT = 1,
    XROOTD_SREQ_DONE     = 2,
    XROOTD_SREQ_FAILED   = 3,
    XROOTD_SREQ_EXPIRED  = 4
} xrootd_sreq_state_t;

/* The durable on-disk request record (Appendix I; persisted by the SP4 queue).
 * Carried in the header now so the seam vocabulary is stable - exactly the
 * "full vocabulary up front, land it incrementally" pattern xfer.h uses. One per
 * transfer; the instance is rebuilt from {driver,key} on replay. */
typedef struct {
    char                 reqid[40];        /* minted request id (NUL-terminated)     */
    xrootd_stage_kind_t  kind;
    xrootd_sreq_state_t  state;
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
} xrootd_sreq_t;

/* Per-submit options. `async` requests park-and-defer (SP4); `conn` is the client
 * connection a parked open is woken on; `open_options` is echoed back to it;
 * `ttl_ms` bounds how long a parked open waits (0 = engine default). */
typedef struct {
    unsigned          async:1;
    off_t             size_hint;
    uint16_t          open_options;
    ngx_connection_t *conn;
    ngx_msec_t        ttl_ms;
    const char       *export_root;   /* anchor to rebuild both tiers on reconcile */
} xrootd_stage_opts_t;

/* The durable queue handle (per export; SP4 owns its storage). Opaque here. */
typedef struct xrootd_stage_queue_s xrootd_stage_queue_t;

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
const char *xrootd_stage_submit(xrootd_stage_kind_t kind,
    xrootd_sd_instance_t *src, const char *src_key,
    xrootd_sd_instance_t *dst, const char *dst_key,
    const xrootd_stage_opts_t *opts);

/*
 * Run a transfer INLINE and return its terminal result - the synchronous path a
 * caller uses when it must know the outcome now (e.g. a sync stage-flush commit).
 * Same generic mover and audit line as xrootd_stage_submit; the difference is the
 * return convention: NGX_OK when the object is durably published on `dst`, else
 * NGX_ERROR (errno set). The async/park path (xrootd_stage_submit) is for when the
 * caller can defer and be woken (SP4).
 */
ngx_int_t xrootd_stage_run_inline(xrootd_stage_kind_t kind,
    xrootd_sd_instance_t *src, const char *src_key,
    xrootd_sd_instance_t *dst, const char *dst_key);

/* Initialise the engine's durable journal directory for this worker (SP4). A
 * NULL/empty dir keeps the async queue in-memory only (no crash recovery). */
void xrootd_stage_engine_init(const char *journal_dir);

/* Per-worker timer hook: drain the deferred (async) queue, running each mover and
 * dropping a completed FLUSH's stage copy (SP4). Bounded per tick. */
void xrootd_stage_scheduler_tick(void);

/* Restart replay: re-submit every in-flight durable request so no transfer is
 * lost across a crash (SP4). SP1 no-op. */
void xrootd_stage_reconcile(xrootd_stage_queue_t *queue);

/* Human string for a kind (audit line + tests). */
const char *xrootd_stage_kind_str(xrootd_stage_kind_t kind);

#endif /* XROOTD_FS_XFER_STAGE_ENGINE_H */
