#ifndef BRIX_AIO_URING_H
#define BRIX_AIO_URING_H

/* ---- File: src/aio/uring.h — optional io_uring disk-I/O backend (Phase 44) ----
 *
 * WHAT: Declares the per-worker io_uring singleton, its completion-slot table,
 *       the op-kind enum, and the public API (runtime probe, startup fail-fast
 *       validation, per-worker lifecycle, the submit/reaper entry points, and
 *       the runtime kill-switch hooks).  The backend is a THIRD AIO dispatch
 *       tier below the existing thread pool: the cascade becomes
 *       io_uring -> thread pool -> inline sync, selected per server block by
 *       `brix_io_uring on|off|auto`.
 *
 * WHY:  The server module never touches a raw socket (nginx core owns egress),
 *       so server-side io_uring is strictly a disk-I/O backend interposed on the
 *       single dispatch seam `brix_aio_post_task()` (src/aio/resume.c).  It is
 *       OFF BY DEFAULT, double-gated (pkg-config liburing at build +
 *       authoritative opcode probe at runtime), and degrades transparently — but
 *       `on` is a hard requirement that fails startup when it cannot be provided
 *       (§32 fail-fast).  See docs/refactor/phase-44-io-uring-backend.md.
 *
 * HOW:  Everything liburing-specific is guarded by BRIX_HAVE_LIBURING.  When
 *       the macro is undefined the whole translation unit compiles to inert
 *       stubs: the worker accessor returns NULL, the probe returns 0, and the
 *       validator hard-fails any `brix_io_uring on` block at config time with
 *       no kernel needed (so `nginx -t` flags a stub build anywhere).  Assumes
 *       ngx_brix_module.h (nginx + config + tunables) is already included. */

#if (BRIX_HAVE_LIBURING)
#include <liburing.h>

/*
 * Completion-slot table entry (UAF-safe task mapping).
 *
 * Never put a raw task pointer in a CQE's user_data: a late completion for a
 * connection that has since been torn down would dereference freed memory.
 * Instead user_data = ((uint64_t)generation << 32) | slot_index; the reaper
 * validates the generation and drops a stale CQE.  This guards the ring slot;
 * the done-callback's own ctx->destroyed check remains the authoritative guard
 * for the connection (both layers are kept).
 */
typedef struct {
    void                 *task;       /* ngx_thread_task_t carrying the *_aio_t */
    ngx_event_handler_pt  done_fn;    /* brix_*_aio_done                      */
    void                 *owner;      /* ngx_connection_t* whose pool holds task*/
    uint32_t              generation; /* bumped on free -> detects a stale CQE  */
    uint8_t               op_kind;    /* brix_uring_op_e; selects OUT xlation */
    uint8_t               in_use;     /* 1 = claimed & submitted, 0 = free      */
    uint8_t               orphaned;   /* 1 = owner torn down; drop CQE unseen   */
} brix_uring_slot_t;

/*
 * Per-worker io_uring singleton.  One ring per worker process (same lifetime as
 * every other per-worker async resource), reached only through the file-static
 * accessor brix_uring_worker() — no new exported global.  Only the event
 * thread mutates the ring (submit on dispatch, reap on the eventfd handler).
 */
typedef struct {
    struct io_uring      ring;          /* liburing SQ/CQ rings                  */
    int                  eventfd;       /* CQE notifier (register_eventfd)       */
    ngx_connection_t    *evc;           /* fake connection wrapping the eventfd  */
    uint32_t             queue_depth;   /* SQ entries; also slot-table length    */
    uint32_t             inflight;      /* SQEs submitted, CQEs not yet reaped   */
    brix_uring_slot_t *slots;         /* completion-slot table, queue_depth    */
    ngx_atomic_t        *disabled_flag; /* SHM hot kill-switch (read each submit)*/
    unsigned             ring_active:1;  /* io_uring_queue_init succeeded         */
    unsigned             enabled:1;     /* ring up & probe passed this worker    */
    unsigned             restrict_ops:1;/* io_uring_register_restrictions applied*/
    ngx_log_t           *log;           /* worker cycle log (for the reaper)     */
} brix_uring_t;

#endif /* BRIX_HAVE_LIBURING */

/*
 * Op-kind discriminator.  XRD_URING_OP_NONE is the sentinel for "not mapped to
 * io_uring" — the selector routes it to the thread pool.  Declared
 * unconditionally so the selector in resume.c can name it in a stub build.
 */
typedef enum {
    XRD_URING_OP_READ = 0,   /* IORING_OP_READ   -> brix_read_aio_t           */
    XRD_URING_OP_WRITE,      /* IORING_OP_WRITE  -> brix_write_aio_t          */
    XRD_URING_OP_READV,      /* IORING_OP_READV  -> brix_readv_aio_t          */
    XRD_URING_OP_WRITEV,     /* IORING_OP_WRITEV -> brix_writev_aio_t (+FSYNC)*/
    XRD_URING_OP_NONE        /* not mapped; selector falls back to the pool     */
} brix_uring_op_e;


/* ---- Public API (all safe to call in a stub build) ---- */

/*
 * Authoritative runtime probe, memoized per process.  Attempts a throwaway
 * io_uring_queue_init(8) + io_uring_get_probe and checks the required server
 * opcodes (READ/WRITE/READV/WRITEV/FSYNC).  NEVER parses uname — containers and
 * seccomp routinely block io_uring_setup even on a new kernel.  Returns 1 iff
 * the ring can be created and all required opcodes are supported; 0 otherwise
 * (and in any stub build).
 */
ngx_int_t brix_uring_runtime_available(void);

/*
 * Startup fail-fast (§32, ADR-16, REQ-IOURING-FAILFAST).  Called from
 * postconfiguration.  If any enabled server block requests `brix_io_uring on`
 * and the backend is not compiled in OR the runtime probe fails, logs
 * NGX_LOG_EMERG with the cause + remedy and returns NGX_ERROR (so `nginx -t`
 * exits non-zero and the master refuses to start).  `off`/`auto` always pass.
 */
ngx_int_t brix_uring_validate_conf(ngx_conf_t *cf);

/*
 * Per-worker lifecycle (SB-W2).  Create/destroy the ring + eventfd bridge after
 * fork / before exit.  In a stub build both are no-ops returning NGX_OK.
 */
ngx_int_t brix_uring_init_worker(ngx_cycle_t *cycle);
void      brix_uring_exit_worker(ngx_cycle_t *cycle);

/* ---- Runtime kill switch + panic-file + admin gate (SB-W5b) ----
 * All build-independent (a cross-worker ngx_atomic_t in SHM; no liburing types),
 * so the HTTP dashboard module can drive the switch without depending on
 * liburing.  In a stub build the zone is simply never registered and set/ptr
 * report "not configured".  See src/aio/uring_admin.c. */

/* Register the SHM zone holding the cross-worker disable flag (postconfiguration,
 * liburing builds with io_uring-wanting blocks only). */
ngx_int_t     brix_uring_killswitch_configure(ngx_conf_t *cf);
/* The flag pointer for this process (NULL when not configured). */
ngx_atomic_t *brix_uring_killswitch_ptr(void);
/* Set/read the cross-worker disable flag. set returns NGX_DECLINED if the zone
 * was never configured (stub build / io_uring off everywhere). */
ngx_int_t     brix_uring_killswitch_set(ngx_uint_t disabled);
ngx_int_t     brix_uring_killswitch_get(void);
/* Arm a per-worker poll timer that mirrors the existence of `path` into the
 * disable flag (the "drop a file at 2 a.m." switch).  No-op for an empty path. */
ngx_int_t     brix_uring_panicfile_arm(ngx_cycle_t *cycle, ngx_str_t *path);
/* Whether `brix_io_uring_admin on` exposed the admin endpoint (set at config
 * time; read by the dashboard handler). */
void          brix_uring_admin_set_enabled(ngx_uint_t on);
ngx_int_t     brix_uring_admin_enabled(void);

#if (BRIX_HAVE_LIBURING)

/* Sentinel user_data for the trailing IORING_OP_FSYNC of a linked
 * writev+fsync chain (SB-W4).  It carries no slot: the reaper recognises it,
 * drops the CQE (fsync is best-effort, matching the thread-pool path's ignored
 * return), and decrements inflight.  Distinct from any real slot cookie (whose
 * low 32 bits are an index < queue_depth). */
#define BRIX_URING_FSYNC_COOKIE  0xfffffffffffffffeULL

/*
 * File-static per-worker accessor.  Returns the live ring for this worker, or
 * NULL when io_uring is disabled/unavailable in this process (the selector then
 * skips the uring tier).  Defined only in a liburing build; the selector guards
 * its use with BRIX_HAVE_LIBURING.
 */
brix_uring_t *brix_uring_worker(void);

/* Completion-slot table helpers shared by the submit path (uring_submit.c) and
 * the reaper (uring.c).  acquire claims the first free slot (NULL if full);
 * release frees it and bumps its generation to invalidate any late CQE. */
brix_uring_slot_t *brix_uring_slot_acquire(brix_uring_t *u,
    uint32_t *idx_out);
void brix_uring_slot_release(brix_uring_t *u, uint32_t idx);

/*
 * brix_uring_disabled — lock-free read of the SHM hot kill-switch (SB-W5b).
 * Returns non-zero when io_uring has been disabled fleet-wide at runtime (admin
 * API or panic-file).  The flag pointer is NULL until SB-W5b wires the SHM
 * atomic, so this reads 0 (enabled) until then.
 */
static ngx_inline ngx_int_t
brix_uring_disabled(brix_uring_t *u)
{
    return u->disabled_flag != NULL && *u->disabled_flag != 0;
}

/*
 * brix_uring_op_for — map a bound thread task to its io_uring op-kind by its
 * worker-fn identity (the fn the task was bound to *is* the op identity, so call
 * sites and task structs need zero changes).  Returns XRD_URING_OP_NONE for any
 * op not mapped to io_uring (pgread/dirlist, and multi-fd/multi-group readv/
 * writev) — the selector then routes it to the thread pool.
 */
brix_uring_op_e brix_uring_op_for(ngx_thread_task_t *task);

/*
 * brix_uring_submit — build + submit one SQE (or a linked chain) for a mapped
 * task.  Sets *posted = 1 on success (the CQE will drive the task's existing
 * done-callback via the reaper); leaves *posted = 0 on any prep/submit failure
 * so the caller falls through to the thread pool.  Always returns NGX_OK.
 */
ngx_int_t brix_uring_submit(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_task_t *task, brix_uring_op_e op, ngx_flag_t *posted);

/*
 * brix_uring_orphan_owner — sever every in-flight uring op owned by a dying
 * connection.  Called from the disconnect path BEFORE the connection pool is
 * destroyed: a late CQE for an orphaned slot is dropped by the reaper without
 * dereferencing the task (whose memory dies with the pool) and without posting
 * its completion event (whose ngx_event_t lives inside that task — posting it
 * after the pool is gone corrupts ngx_posted_events, the xrd1 crash-loop).
 * No-op when the ring is down or nothing is in flight for this owner.
 */
void brix_uring_orphan_owner(void *owner);
#endif

#endif /* BRIX_AIO_URING_H */
