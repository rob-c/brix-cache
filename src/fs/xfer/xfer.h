/*
 * xfer.h — public contract for the unified durable-transfer engine.
 *
 * WHAT: One state machine (BEGIN -> MOVE -> COMMIT|ABORT) that the four durable
 *       write/transfer paths — normal staging, tape stage-out, proxy
 *       write-through, and TPC — are thin configurations of. This header is the
 *       only surface callers and movers share; the state-machine internals live
 *       in xfer_core.c, the byte movers in xfer_mover_*.c, audit in
 *       xfer_ledger.c, policy in xfer_policy.c, durability in xfer_journal.c /
 *       xfer_reconcile.c.
 *
 * WHY:  Four subsystems each re-implemented commit/abort, confinement, async
 *       durability, external-process execution, and their own audit record. That
 *       fragmentation is the support burden (four places crash-safety can be
 *       wrong, two fork/reap models — only one crash-safe) and the auditing
 *       burden (four metric families, one access-log schema). This engine
 *       collapses them onto one envelope. See
 *       docs/superpowers/specs/2026-06-28-unified-durable-transfer-engine-design.md.
 *
 * HOW:  The engine is introduced incrementally (spec §9). This header carries the
 *       full vocabulary up front so the seam is stable, but only the symbols a
 *       given phase has landed are defined in the .c files. Phase 1 lands the
 *       in-process pump mover (brix_xfer_pump_objects) extracted from
 *       compat/staged_file.c.
 */

#ifndef BRIX_FS_XFER_H
#define BRIX_FS_XFER_H

#include <ngx_core.h>

#include "fs/backend/sd.h"   /* brix_sd_obj_t — the byte-movable object handle */

/* The transfer kind. Drives the per-kind metric callback (ledger) and the
 * server-driven vs client-driven recovery split (reconcile). */
typedef enum {
    BRIX_XFER_STAGE = 0,   /* client stream -> local object (S3/WebDAV/root PUT) */
    BRIX_XFER_TAPE,        /* tape copycmd -> local (server-driven, async)       */
    BRIX_XFER_WT,          /* local cache file -> remote origin (write-through)  */
    BRIX_XFER_TPC          /* third-party copy (curl)                            */
} brix_xfer_kind_t;

/* How bytes move. Exactly two implementations — an in-process SD pump, and the
 * single crash-safe out-of-process agent harness (extracted from frm/stage.c)
 * shared by every external-process transfer. */
typedef enum {
    BRIX_XFER_MOVE_PUMP = 0,   /* in-process src->driver->pread/pwrite           */
    BRIX_XFER_MOVE_AGENT       /* delegated argv via the reparented stage agent  */
} brix_xfer_mover_t;

/* Policy disposition decided at BEGIN (generalized from writethrough_decision). */
typedef enum {
    BRIX_XFER_SYNC = 0,    /* move now, in-line                                  */
    BRIX_XFER_ASYNC,       /* enqueue on the durable journal, return DEFERRED    */
    BRIX_XFER_DENY         /* policy refuses this destination                    */
} brix_xfer_disp_t;

/* Terminal result. Each protocol edge maps this to its own wire status via the
 * existing errno -> kXR -> HTTP table; the engine adds no new edge vocabulary. */
typedef enum {
    BRIX_XFER_OK = 0,
    BRIX_XFER_DEFERRED,    /* admitted to the async journal; completes later     */
    BRIX_XFER_DENIED,
    BRIX_XFER_SRC_ERR,
    BRIX_XFER_DST_ERR,
    BRIX_XFER_COMMIT_ERR,
    BRIX_XFER_AGENT_FAIL
} brix_xfer_result_t;

/*
 * Phase 1 — the delegated out-of-process agent harness.
 *
 * The single crash-safe way to run an external transfer process from an nginx
 * worker. nginx's master SIGCHLD handler walks every SHM zone as an
 * ngx_slab_pool_t and force-unlocks it; several module zones overwrite that
 * header, so reaping ANY worker child SIGSEGVs the master. The agent is
 * double-forked (reparented to init) so nginx never reaps it, and the agent —
 * not nginx — reaps the transfer-command children. All blocking work
 * (fork/exec/waitpid) runs in the agent, off the event loop, with no thread pool.
 *
 * Originally embedded in src/frm/stage.c for tape recall; lifted here so every
 * external-process transfer (tape copycmd, write-through origin client, TPC curl)
 * shares ONE fork/reap path. The harness is payload-agnostic: it shuttles
 * fixed-size request/reply frames and invokes per-kind callbacks. Because the
 * agent is a fork() (not exec), the callback function pointers are valid in the
 * child.
 */

/* Per-kind agent behaviour. process() runs in the reparented AGENT (off the
 * event loop; may fork/exec/waitpid its own children — SIGCHLD is SIG_DFL there).
 * on_reply() and after_drain() run in the WORKER on the event loop. `data` is an
 * opaque pointer passed to all three; agent-side mutations do not propagate back
 * across the fork. */
typedef struct {
    size_t      req_size;        /* bytes per request frame                      */
    size_t      rep_size;        /* bytes per reply frame                        */
    void      (*process)(const void *req, void *rep, void *data);   /* agent     */
    void      (*on_reply)(const void *rep, void *data);             /* worker    */
    void      (*after_drain)(void *data);          /* worker, optional (may be 0) */
    void       *data;
    const char *name;            /* for log lines, e.g. "frm stage"              */
} brix_xfer_agent_ops_t;

/* Worker-side handle for one agent. Zero-initialize before first attach; `fd < 0`
 * means "no live agent" so dispatch fails closed. */
typedef struct {
    int                            fd;       /* worker side of socketpair, or -1 */
    ngx_connection_t              *conn;      /* nginx read-event connection      */
    const brix_xfer_agent_ops_t *ops;
    ngx_log_t                     *log;
    void                          *rep_buf;   /* worker reply scratch, rep_size   */
} brix_xfer_agent_t;

/* Spawn a reparented agent and register the worker side of its socketpair as an
 * nginx read event. On any failure tears down and leaves a->fd = -1 (dispatch
 * fails closed). Returns NGX_OK / NGX_ERROR. Also used internally for respawn. */
ngx_int_t brix_xfer_agent_attach(brix_xfer_agent_t *a,
    const brix_xfer_agent_ops_t *ops, ngx_log_t *log);

/* Release the worker side (closes fd + frees the connection). Idempotent; the
 * reparented agent observes EOF and exits on its own. */
void brix_xfer_agent_teardown(brix_xfer_agent_t *a);

/* Send one request frame (a->ops->req_size bytes) to the agent. Returns NGX_OK
 * sent, NGX_AGAIN if the agent is backed up (retry later), NGX_ERROR on a dead
 * or broken agent. */
ngx_int_t brix_xfer_agent_dispatch(brix_xfer_agent_t *a, const void *req);

/* ===================== Phase 2: the unified audit ledger =================== */

/*
 * One audit event, recorded at a transfer's terminal COMMIT or ABORT.
 *
 * Per the approved ledger model, metrics keep their existing per-subsystem names
 * (each caller books its own as before — e.g. STAGE still books OP_WRITE); the
 * ledger's contribution is the ONE consistent audit line emitted for every kind,
 * so an operator has a single place to answer "what was published, by whom, by
 * which path". The line is transport-agnostic — it works identically for stream
 * root:// callers and HTTP S3/WebDAV callers, which have separate per-protocol
 * access logs.
 */
typedef struct {
    brix_xfer_kind_t    kind;
    const char           *direction;   /* "in" (into our storage) | "out"       */
    const char           *path;        /* final object path (sanitized on emit) */
    const char           *principal;   /* authenticated identity, or NULL ("-")  */
    size_t                bytes;        /* committed object size                  */
    brix_xfer_result_t  result;
    int                   sys_errno;    /* meaningful when result != OK           */
    ngx_log_t            *log;
} brix_xfer_audit_t;

/* Append one unified audit line for a terminal transfer. Best-effort: a sink it
 * cannot open is warned once and skipped (auditing never blocks a transfer). The
 * sink path is $BRIX_XFER_AUDIT_LOG, else <prefix>/logs/xfer_audit.log. */
void brix_xfer_ledger_record(const brix_xfer_audit_t *ev);

/* Stable human strings for a kind / result (used in the audit line and tests). */
const char *brix_xfer_kind_str(brix_xfer_kind_t kind);
const char *brix_xfer_result_str(brix_xfer_result_t result);

/* ===================== Phase 4: the engine terminal chokepoint ============= */

/*
 * Record a transfer reaching a terminal state. Every kind (STAGE/TAPE/WT, and
 * later TPC) calls this at commit/abort instead of building an audit struct
 * inline — one place, so the audit schema and (in a later step) the durable
 * journal completion update have a single hook. Thin today (it emits the unified
 * ledger line); it is the seam the journal/reconcile work attaches to without
 * touching any caller again.
 */
void brix_xfer_finish(brix_xfer_kind_t kind, const char *direction,
    const char *path, const char *principal, size_t bytes,
    brix_xfer_result_t result, int sys_errno, ngx_log_t *log);

/* ===================== housekeeping ====================================== */

/* Arm the worker-0 TTL sweep of abandoned upload-resume partials
 * (`*.xrdresume.part`) in `stage_dir`. No-op without a stage dir, off worker 0,
 * or when $BRIX_UPLOAD_RESUME_TTL is 0. (xfer_resume_sweep.c) */
void brix_xfer_resume_sweep_register(ngx_cycle_t *cycle, const char *stage_dir);

/*
 * Phase 1 — the in-process byte pump.
 *
 * Copy the whole source object into the destination object by reading through
 * the SOURCE object's storage driver and writing through the DESTINATION
 * object's driver. The two objects may live on different backends — this is the
 * cross-mount move at the heart of every staged commit, so it is exactly where
 * one side could later be an object/S3 store while the other stays POSIX. All
 * raw byte I/O stays inside the SD backends (sd_posix.c et al.); this loop is
 * driver-mediated and never touches a raw fd directly.
 *
 * Returns NGX_OK, or NGX_ERROR with errno set. EINTR is retried.
 */
ngx_int_t brix_xfer_pump_objects(brix_sd_obj_t *src, brix_sd_obj_t *dst);

#endif /* BRIX_FS_XFER_H */
